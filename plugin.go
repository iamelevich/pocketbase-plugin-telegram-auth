package pocketbase_plugin_telegram_auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/iamelevich/pocketbase-plugin-telegram-auth/forms"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/auth"
	"golang.org/x/oauth2"
)

// telegramProvider is a minimal auth.Provider implementation for validation.
// It exists so "telegram" is recognized in auth.Providers for ExternalAuth records.
// The actual auth flow is handled by the plugin's custom endpoint, not OAuth2.
type telegramProvider struct {
	auth.BaseProvider
}

func (p *telegramProvider) FetchAuthUser(_ *oauth2.Token) (*auth.AuthUser, error) {
	return nil, errors.New("telegram auth uses custom flow, not OAuth2")
}

// Options defines optional struct to customize the default plugin behavior.
type Options struct {
	// BotToken is a Telegram bot token.
	// You can get it from @BotFather.
	BotToken string

	// CollectionKey is a collection key (name or id) for PocketBase auth collection.
	CollectionKey string
}

type Plugin struct {
	app        core.App
	options    *Options
	collection *core.Collection
}

// Validate plugin options. Return error if some option is invalid.
func (p *Plugin) Validate() error {
	if p.options == nil {
		return fmt.Errorf("options is required")
	}

	if p.options.BotToken == "" {
		return fmt.Errorf("bot token is required")
	}

	if p.options.CollectionKey == "" {
		return fmt.Errorf("collection key is required")
	}

	return nil
}

// GetCollection returns PocketBase collection object for collection with name or id from options.CollectionKey.
func (p *Plugin) GetCollection() (*core.Collection, error) {
	// If collection object stored in plugin - return it
	if p.collection != nil {
		return p.collection, nil
	}

	// If no collection object - find it, store and return
	if collection, err := p.app.FindCollectionByNameOrId(p.options.CollectionKey); err != nil {
		return nil, err
	} else {
		p.collection = collection
		return collection, nil
	}
}

// GetForm returns Telegram login form for collection with name or id from options.CollectionKey.
func (p *Plugin) GetForm(optAuthRecord *core.Record) (*forms.RecordTelegramLogin, error) {
	collection, findCollectionErr := p.GetCollection()
	if findCollectionErr != nil {
		return nil, findCollectionErr
	}
	if collection.Type != core.CollectionTypeAuth {
		return nil, errors.New("Wrong collection type. " + p.options.CollectionKey + " should be auth collection")
	}

	return forms.NewRecordTelegramLogin(p.app, p.options.BotToken, collection, optAuthRecord), nil
}

// AuthByTelegramData returns auth record and auth user by Telegram data.
func (p *Plugin) AuthByTelegramData(tgData forms.TelegramData) (*core.Record, *auth.AuthUser, error) {
	form, err := p.GetForm(nil)
	if err != nil {
		return nil, nil, err
	}

	return form.SubmitWithTelegramData(&tgData)
}

// MustRegister is a helper function to register plugin and panic if error occurred.
func MustRegister(app core.App, options *Options) *Plugin {
	if p, err := Register(app, options); err != nil {
		panic(err)
	} else {
		return p
	}
}

// Register plugin in PocketBase app.
func Register(app core.App, options *Options) (*Plugin, error) {
	p := &Plugin{app: app}

	// Set default options
	if options != nil {
		p.options = options
	} else {
		p.options = &Options{}
	}

	// Validate options
	if err := p.Validate(); err != nil {
		return p, err
	}

	auth.Providers["telegram"] = func() auth.Provider {
		// Minimal provider for ExternalAuth validation (core/external_auth_model.go).
		// Actual auth is handled by the plugin's custom endpoint, not OAuth2.
		provider := &telegramProvider{}
		provider.SetDisplayName("Telegram")
		provider.SetClientId("telegram")
		provider.SetContext(context.Background())
		return provider
	}

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		path := "/api/collections/" + p.options.CollectionKey + "/auth-with-telegram"
		se.Router.POST(path, func(e *core.RequestEvent) error {
			collection, findCollectionErr := p.GetCollection()
			if findCollectionErr != nil {
				return e.NotFoundError("Collection not found", findCollectionErr)
			}

			var fallbackAuthRecord *core.Record
			if e.Auth != nil && e.Auth.Collection().Id == collection.Id {
				fallbackAuthRecord = e.Auth
			}

			form, getFormErr := p.GetForm(fallbackAuthRecord)
			if getFormErr != nil {
				// log.Default().Println("Error getting form", "err", getFormErr)
				return e.BadRequestError(getFormErr.Error(), getFormErr)
			}
			if err := e.BindBody(form); err != nil {
				// log.Default().Println("Error binding body", "err", err)
				return e.BadRequestError("Failed to read request data", err)
			}

			record, _, submitErr := form.Submit()
			if submitErr != nil {
				// log.Default().Println("Error submitting form", "err", submitErr)
				return e.BadRequestError("Failed to authenticate.", submitErr)
			}

			meta := map[string]any{"isNew": record.IsNew()}
			return apis.RecordAuthResponse(e, record, "telegram", meta)
		})
		return se.Next()
	})

	return p, nil
}
