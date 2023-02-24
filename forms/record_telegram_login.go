package forms

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/daos"
	pbForms "github.com/pocketbase/pocketbase/forms"
	"github.com/pocketbase/pocketbase/models"
	"github.com/pocketbase/pocketbase/tools/auth"
	"github.com/pocketbase/pocketbase/tools/security"
)

// RecordTelegramLogin is an auth record Telegram login form.
type RecordTelegramLogin struct {
	app        core.App
	dao        *daos.Dao
	collection *models.Collection
	botToken   string

	// Optional auth record that will be used if no external
	// auth relation is found (if it is from the same collection)
	loggedAuthRecord *models.Record

	// Telegram data from window.Telegram.WebApp.initData in Web App
	// This is URL encoded string with all telegram data.
	// It should have hash inside
	Data string `form:"data" json:"data"`

	// The version of the Bot API available in the user's Telegram app. Can be empty
	Version string `form:"version" json:"version"`

	// The name of the platform of the user's Telegram app. Can be empty
	Platform string `form:"platform" json:"platform"`

	// Additional data that will be used for creating a new auth record
	// if an existing Telegram account doesn't exist.
	CreateData map[string]any `form:"createData" json:"createData"`
}

type TelegramData struct {
	Id           int64  `json:"id"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	Username     string `json:"username"`
	LanguageCode string `json:"language_code"`
	PhotoUrl     string `json:"photo_url"`
}

// NewRecordTelegramLogin creates a new [RecordTelegramLogin] form with
// initialized with from the provided [core.App] instance.
//
// If you want to submit the form as part of a transaction,
// you can change the default Dao via [SetDao()].
func NewRecordTelegramLogin(app core.App, botToken string, collection *models.Collection, optAuthRecord *models.Record) *RecordTelegramLogin {
	form := &RecordTelegramLogin{
		app:              app,
		botToken:         botToken,
		collection:       collection,
		dao:              app.Dao(),
		loggedAuthRecord: optAuthRecord,
	}

	return form
}

// SetDao replaces the default form Dao instance with the provided one.
func (form *RecordTelegramLogin) SetDao(dao *daos.Dao) {
	form.dao = dao
}

// Validate makes the form validatable by implementing [validation.Validatable] interface.
func (form *RecordTelegramLogin) Validate() error {
	return validation.ValidateStruct(form,
		validation.Field(&form.Data, validation.Required, validation.By(form.checkTelegramData)),
	)
}

func (form *RecordTelegramLogin) checkTelegramData(value any) error {
	data, _ := value.(string)

	if result, err := form.checkTelegramAuthorization(data); !result || err != nil {
		return validation.NewError("validation_invalid_data", "Provided data is invalid.")
	}

	return nil
}

// checkTelegramAuthorization data param. Check https://core.telegram.org/bots/webapps#validating-data-received-via-the-web-app
func (form *RecordTelegramLogin) checkTelegramAuthorization(data string) (bool, error) {
	// Parse string
	params, err := url.ParseQuery(data)
	if err != nil {
		return false, err
	}
	strs := []string{}
	var hashFromTelegram = ""
	// Extract hashFromTelegram and create slice of other params
	for k, v := range params {
		if k == "hash" {
			hashFromTelegram = v[0]
			continue
		}
		strs = append(strs, k+"="+v[0])
	}
	// Sort extracted params
	sort.Strings(strs)
	// Create a string with params to validate
	var imploded = ""
	for _, s := range strs {
		if imploded != "" {
			imploded += "\n"
		}
		imploded += s
	}

	// Create hashFromTelegram to check is provided data valid
	token := form.botToken
	generatedHash := ""
	var secretKey hash.Hash
	if _, ok := params["user"]; ok {
		// Check is it web app data need to use HMAC_SHA256
		secretKey = hmac.New(sha256.New, []byte("WebAppData"))
	} else {
		// this is login button data, should use SHA256
		secretKey = sha256.New()
	}
	if _, err = io.WriteString(secretKey, token); err != nil {
		return false, err
	}
	resultHash := hmac.New(sha256.New, secretKey.Sum(nil))
	if _, err = io.WriteString(resultHash, imploded); err != nil {
		return false, err
	}
	generatedHash = hex.EncodeToString(resultHash.Sum(nil))
	return hashFromTelegram == generatedHash, nil
}

// GetAuthUserFromData Parse Data url encoded values to the stuct with user data
func (form *RecordTelegramLogin) GetAuthUserFromData() (*auth.AuthUser, error) {
	authUser := auth.AuthUser{}

	params, err := url.ParseQuery(form.Data)
	if err != nil {
		return &authUser, err
	}

	// Set RawUser data
	authUser.RawUser = map[string]any{}
	for k, v := range params {
		authUser.RawUser[k] = v[0]
	}

	// Set CreateData
	form.CreateData = map[string]any{}

	// If we have user param - this is data from WebApp https://core.telegram.org/bots/webapps#webappinitdata
	if v, ok := params["user"]; ok {
		telegramData := TelegramData{}
		if err = json.Unmarshal([]byte(v[0]), &telegramData); err != nil {
			return &authUser, err
		}
		authUser.Id = strconv.FormatInt(telegramData.Id, 10)
		authUser.Username = telegramData.Username
		authUser.Name = strings.TrimSpace(telegramData.FirstName + " " + telegramData.LastName)
		authUser.AvatarUrl = telegramData.PhotoUrl

		// Fill CreateData
		form.CreateData["name"] = authUser.Name
		form.CreateData["first_name"] = telegramData.FirstName
		form.CreateData["last_name"] = telegramData.LastName
		form.CreateData["telegram_username"] = authUser.Username
		form.CreateData["telegram_id"] = authUser.Id
		form.CreateData["language_code"] = telegramData.LanguageCode

		return &authUser, nil
	}

	// If this is data from widget - all data on to level
	firstName := ""
	lastName := ""
	for k, v := range params {
		switch k {
		case "id":
			authUser.Id = v[0]
		case "first_name":
			firstName = v[0]
		case "last_name":
			lastName = v[0]
		case "username":
			authUser.Username = v[0]
		case "language_code":
			form.CreateData["language_code"] = v[0]
		case "photo_url":
			authUser.AvatarUrl = v[0]
		}
	}
	authUser.Name = strings.TrimSpace(firstName + " " + lastName)

	// Fill CreateData
	form.CreateData["name"] = authUser.Name
	form.CreateData["first_name"] = firstName
	form.CreateData["last_name"] = lastName
	form.CreateData["telegram_username"] = authUser.Username
	form.CreateData["telegram_id"] = authUser.Id

	return &authUser, nil
}

// Submit validates and submits the form.
//
// If an auth record doesn't exist, it will make an attempt to create it
// based on the fetched Telegram profile data via a local [RecordUpsert] form.
// You can intercept/modify the create form by setting the optional beforeCreateFuncs argument.
//
// On success returns the authorized record model and the fetched provider's data.
func (form *RecordTelegramLogin) Submit(
	beforeCreateFuncs ...func(createForm *pbForms.RecordUpsert, authRecord *models.Record, authUser *auth.AuthUser) error,
) (*models.Record, *auth.AuthUser, error) {
	if err := form.Validate(); err != nil {
		return nil, nil, err
	}

	authUser, err := form.GetAuthUserFromData()
	if err != nil {
		return nil, nil, err
	}

	var authRecord *models.Record

	// check for existing relation with the auth record
	rel, _ := form.dao.FindExternalAuthByProvider("telegram", authUser.Id)
	if rel != nil {
		authRecord, err = form.dao.FindRecordById(form.collection.Id, rel.RecordId)
		if err != nil {
			return nil, authUser, err
		}
	} else {
		// Try to find record by telegram_id field if exists
		authRecord, _ = form.dao.FindFirstRecordByData(form.collection.Id, "telegram_id", authUser.Id)
	}

	// fallback to the logged auth record (if any)
	if authRecord == nil && form.loggedAuthRecord != nil && form.loggedAuthRecord.Collection().Id == form.collection.Id {
		authRecord = form.loggedAuthRecord
	}

	saveErr := form.dao.RunInTransaction(func(txDao *daos.Dao) error {
		if authRecord == nil {
			authRecord = models.NewRecord(form.collection)
			authRecord.RefreshId()
			authRecord.MarkAsNew()
			createForm := pbForms.NewRecordUpsert(form.app, authRecord)
			createForm.SetFullManageAccess(true)
			createForm.SetDao(txDao)
			if authUser.Username != "" && regexp.MustCompile(`^\w[\w.]*$`).MatchString(authUser.Username) {
				createForm.Username = form.dao.SuggestUniqueAuthRecordUsername(form.collection.Id, authUser.Username)
			}

			// load custom data
			if err := createForm.LoadData(form.CreateData); err != nil {
				return err
			}

			// load the Telegram profile data as fallback
			if createForm.Password == "" {
				createForm.Password = security.RandomString(30)
				createForm.PasswordConfirm = createForm.Password
			}

			for _, f := range beforeCreateFuncs {
				if f == nil {
					continue
				}
				if err := f(createForm, authRecord, authUser); err != nil {
					return err
				}
			}

			// create the new auth record
			if err := createForm.Submit(); err != nil {
				return err
			}
		}

		// create ExternalAuth relation if missing
		if rel == nil {
			rel = &models.ExternalAuth{
				CollectionId: authRecord.Collection().Id,
				RecordId:     authRecord.Id,
				Provider:     "telegram",
				ProviderId:   authUser.Id,
			}
			if err := txDao.SaveExternalAuth(rel); err != nil {
				return err
			}
		}

		return nil
	})

	if saveErr != nil {
		return nil, authUser, saveErr
	}

	return authRecord, authUser, nil
}
