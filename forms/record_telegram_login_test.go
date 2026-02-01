package forms_test

import (
	"encoding/json"
	"reflect"
	"testing"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	pocketbase_plugin_telegram_auth "github.com/iamelevich/pocketbase-plugin-telegram-auth"
	"github.com/iamelevich/pocketbase-plugin-telegram-auth/forms"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/auth"
)

func TestUserTelegramLoginValidate(t *testing.T) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	scenarios := []struct {
		testName       string
		collectionName string
		jsonData       string
		expectedErrors []string
	}{
		{
			"empty payload",
			"users",
			"{}",
			[]string{"data"},
		},
		{
			"empty data",
			"users",
			`{"data":""}`,
			[]string{"data"},
		},
		{
			"invalid data",
			"users",
			`{"data":"invalid"}`,
			[]string{"data"},
		},
		{
			"valid data web auth",
			"users",
			`{"data": "query_id=AAGSTRQLAAAAAJJNFAsbizs2&user=%7B%22id%22%3A185879954%2C%22first_name%22%3A%22Ilya%22%2C%22last_name%22%3A%22%22%2C%22username%22%3A%22beer13%22%2C%22language_code%22%3A%22ru%22%7D&auth_date=1673317539&hash=74e1b67c230d2343f5d317a4d77841e9c673cae1bde28606a40825a98c7be638"}`,
			[]string{},
		},
		{
			"valid data login widget",
			"users",
			`{"data":"id=185879954&first_name=Ilya&last_name=&username=beer13&language_code=ru&hash=bf8e28bc7dfed2415ef50b70b2ed64759a94cd4ff647fec150cbc721f988066a"}`,
			[]string{},
		},
	}

	for _, s := range scenarios {
		authCollection, _ := app.FindCollectionByNameOrId(s.collectionName)
		if authCollection == nil {
			t.Errorf("[%s] Failed to fetch auth collection", s.testName)
		}

		form := forms.NewRecordTelegramLogin(app, "test", authCollection, nil)

		// load data
		loadErr := json.Unmarshal([]byte(s.jsonData), form)
		if loadErr != nil {
			t.Errorf("[%s] Failed to load form data: %v", s.testName, loadErr)
			continue
		}

		err := form.Validate()

		// parse errors
		errs, ok := err.(validation.Errors)
		if !ok && err != nil {
			t.Errorf("[%s] Failed to parse errors %v", s.testName, err)
			continue
		}

		// check errors
		if len(errs) > len(s.expectedErrors) {
			t.Errorf("[%s] Expected error keys %v, got %v", s.testName, s.expectedErrors, errs)
		}
		for _, k := range s.expectedErrors {
			if _, ok := errs[k]; !ok {
				t.Errorf("[%s] Missing expected error key %q in %v", s.testName, k, errs)
			}
		}
	}
}

func TestUserTelegramGetDataParsed(t *testing.T) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	scenarios := []struct {
		testName       string
		collectionName string
		jsonData       string
		expectedOutput auth.AuthUser
	}{
		{
			"web app data",
			"users",
			`{"data":"query_id=AAGSTRQLAAAAAJJNFAsbizs2&user=%7B%22id%22%3A185879954%2C%22first_name%22%3A%22Ilya%22%2C%22last_name%22%3A%22%22%2C%22username%22%3A%22beer13%22%2C%22language_code%22%3A%22ru%22%7D&auth_date=1673317539&hash=74e1b67c230d2343f5d317a4d77841e9c673cae1bde28606a40825a98c7be638"}`,
			auth.AuthUser{
				Id:       "185879954",
				Name:     "Ilya",
				Username: "beer13",
				RawUser: map[string]any{
					"auth_date": "1673317539",
					"hash":      "74e1b67c230d2343f5d317a4d77841e9c673cae1bde28606a40825a98c7be638",
					"query_id":  "AAGSTRQLAAAAAJJNFAsbizs2",
					"user":      "{\"id\":185879954,\"first_name\":\"Ilya\",\"last_name\":\"\",\"username\":\"beer13\",\"language_code\":\"ru\"}",
				},
			},
		},
		{
			"login widget data",
			"users",
			`{"data":"id=185879954&first_name=Ilya&last_name=&username=beer13&language_code=ru&hash=bf8e28bc7dfed2415ef50b70b2ed64759a94cd4ff647fec150cbc721f988066a"}`,
			auth.AuthUser{
				Id:       "185879954",
				Name:     "Ilya",
				Username: "beer13",
				RawUser: map[string]any{
					"first_name":    "Ilya",
					"id":            "185879954",
					"language_code": "ru",
					"last_name":     "",
					"username":      "beer13",
					"hash":          "bf8e28bc7dfed2415ef50b70b2ed64759a94cd4ff647fec150cbc721f988066a",
				},
			},
		},
	}

	for _, s := range scenarios {
		authCollection, _ := app.FindCollectionByNameOrId(s.collectionName)
		if authCollection == nil {
			t.Errorf("[%s] Failed to fetch auth collection", s.testName)
		}

		form := forms.NewRecordTelegramLogin(app, "test", authCollection, nil)

		// load data
		loadErr := json.Unmarshal([]byte(s.jsonData), form)
		if loadErr != nil {
			t.Errorf("[%s] Failed to load form data: %v", s.testName, loadErr)
			continue
		}

		authData, parseDataErr := form.GetAuthUserFromData()
		if parseDataErr != nil {
			t.Errorf("[%s] Failed to parse form data: %v", s.testName, parseDataErr)
			continue
		}

		if !reflect.DeepEqual(authData, &s.expectedOutput) {
			t.Errorf("[%s] Auth data not equal. Expected\n %#v\n got\n %#v", s.testName, s.expectedOutput, authData)
		}
	}
}

func TestGetAuthUserFromData_EdgeCases(t *testing.T) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	authCollection, _ := app.FindCollectionByNameOrId("users")
	if authCollection == nil {
		t.Fatal("Failed to fetch auth collection")
	}

	t.Run("invalid user JSON returns error", func(t *testing.T) {
		form := forms.NewRecordTelegramLogin(app, "test", authCollection, nil)
		form.Data = "user=not-valid-json&hash=abc"
		_, err := form.GetAuthUserFromData()
		if err == nil {
			t.Error("Expected error for invalid user JSON")
		}
	})

	t.Run("ParseQuery error returns error", func(t *testing.T) {
		form := forms.NewRecordTelegramLogin(app, "test", authCollection, nil)
		form.Data = "%%%invalid%%%"
		_, err := form.GetAuthUserFromData()
		if err == nil {
			t.Error("Expected error for malformed query string")
		}
	})

	t.Run("widget with photo_url", func(t *testing.T) {
		form := forms.NewRecordTelegramLogin(app, "test", authCollection, nil)
		form.Data = "id=123&first_name=John&last_name=Doe&username=johndoe&language_code=en&photo_url=https://example.com/photo.jpg&hash=ignored"
		authData, err := form.GetAuthUserFromData()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if authData.AvatarUrl != "https://example.com/photo.jpg" {
			t.Errorf("Expected AvatarUrl, got %q", authData.AvatarUrl)
		}
	})
}

func TestSubmit_WithValidData(t *testing.T) {
	app, err := tests.NewTestApp("../test/test_pb_data")
	if err != nil {
		t.Fatalf("Cannot initialize test app: %v", err)
	}
	defer app.Cleanup()

	// Register plugin so "telegram" is valid in auth.Providers for ExternalAuth
	pocketbase_plugin_telegram_auth.MustRegister(app, &pocketbase_plugin_telegram_auth.Options{
		BotToken:      "test",
		CollectionKey: "users",
	})

	authCollection, _ := app.FindCollectionByNameOrId("users")
	if authCollection == nil {
		t.Fatal("Failed to fetch auth collection")
	}

	// Hash in test data was generated with bot token "test"
	form := forms.NewRecordTelegramLogin(app, "test", authCollection, nil)
	form.Data = "query_id=AAGSTRQLAAAAAJJNFAsbizs2&user=%7B%22id%22%3A185879954%2C%22first_name%22%3A%22Ilya%22%2C%22last_name%22%3A%22%22%2C%22username%22%3A%22beer13%22%2C%22language_code%22%3A%22ru%22%7D&auth_date=1673317539&hash=74e1b67c230d2343f5d317a4d77841e9c673cae1bde28606a40825a98c7be638"

	record, authUser, err := form.Submit()
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	if record == nil {
		t.Fatal("Expected record, got nil")
	}
	if authUser == nil {
		t.Fatal("Expected authUser, got nil")
	}
	if authUser.Id != "185879954" {
		t.Errorf("Expected authUser.Id=185879954, got %s", authUser.Id)
	}
}

func TestSubmitWithTelegramData_WithValidData(t *testing.T) {
	app, err := tests.NewTestApp("../test/test_pb_data")
	if err != nil {
		t.Fatalf("Cannot initialize test app: %v", err)
	}
	defer app.Cleanup()

	// Register plugin so "telegram" is valid in auth.Providers for ExternalAuth
	pocketbase_plugin_telegram_auth.MustRegister(app, &pocketbase_plugin_telegram_auth.Options{
		BotToken:      "test_bot_token",
		CollectionKey: "users",
	})

	authCollection, _ := app.FindCollectionByNameOrId("users")
	if authCollection == nil {
		t.Fatal("Failed to fetch auth collection")
	}

	tgData := &forms.TelegramData{
		Id:           999888777,
		FirstName:    "Submit",
		LastName:     "Test",
		Username:     "submit_test",
		LanguageCode: "en",
		PhotoUrl:     "https://t.me/i/userpic.jpg",
	}

	form := forms.NewRecordTelegramLogin(app, "test_bot_token", authCollection, nil)
	record, authUser, err := form.SubmitWithTelegramData(tgData)
	if err != nil {
		t.Fatalf("SubmitWithTelegramData failed: %v", err)
	}
	if record == nil {
		t.Fatal("Expected record, got nil")
	}
	if authUser == nil {
		t.Fatal("Expected authUser, got nil")
	}
	if authUser.Id != "999888777" {
		t.Errorf("Expected authUser.Id=999888777, got %s", authUser.Id)
	}
	if authUser.AvatarUrl != tgData.PhotoUrl {
		t.Errorf("Expected AvatarUrl=%q, got %q", tgData.PhotoUrl, authUser.AvatarUrl)
	}
}

func TestSubmit_WithInvalidData(t *testing.T) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	authCollection, _ := app.FindCollectionByNameOrId("users")
	if authCollection == nil {
		t.Fatal("Failed to fetch auth collection")
	}

	form := forms.NewRecordTelegramLogin(app, "test", authCollection, nil)
	form.Data = "invalid=data&hash=wrong"

	_, _, err := form.Submit()
	if err == nil {
		t.Error("Expected error for invalid data")
	}
}
