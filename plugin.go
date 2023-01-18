package pocketbase_plugin_telegram_auth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/iamelevich/pocketbase-plugin-telegram-auth/forms"
	"github.com/labstack/echo/v5"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/daos"
	pbForms "github.com/pocketbase/pocketbase/forms"
	"github.com/pocketbase/pocketbase/models"
	"github.com/pocketbase/pocketbase/resolvers"
	"github.com/pocketbase/pocketbase/tools/auth"
	"github.com/pocketbase/pocketbase/tools/search"
)

// Options defines optional struct to customize the default plugin behavior.
type Options struct {
	BotToken      string
	CollectionKey string
}

type plugin struct {
	app     core.App
	options *Options
}

func (p *plugin) Validate() error {
	if p.options.BotToken == "" {
		return fmt.Errorf("bot token is required")
	}

	if p.options.CollectionKey == "" {
		return fmt.Errorf("collection key is required")
	}

	return nil
}

func MustRegister(app core.App, options *Options) {
	if err := Register(app, options); err != nil {
		panic(err)
	}
}

func Register(app core.App, options *Options) error {
	p := &plugin{app: app}

	// Set default options
	if options != nil {
		p.options = options
	} else {
		p.options = &Options{}
	}

	// Validate options
	if err := p.Validate(); err != nil {
		return err
	}

	app.OnBeforeServe().Add(func(e *core.ServeEvent) error {
		// or you can also use the shorter e.Router.GET("/articles/:slug", handler, middlewares...)
		_, routeError := e.Router.AddRoute(echo.Route{
			Method: http.MethodPost,
			Path:   "/api/collections/" + p.options.CollectionKey + "/auth-with-telegram",
			Handler: func(c echo.Context) error {
				collection, findCollectionErr := p.app.Dao().FindCollectionByNameOrId(p.options.CollectionKey)
				if findCollectionErr != nil {
					return findCollectionErr
				}
				if collection.Type != models.CollectionTypeAuth {
					return errors.New("Wrong collection type. " + p.options.CollectionKey + " should be auth collection")
				}
				var fallbackAuthRecord *models.Record

				loggedAuthRecord, _ := c.Get(apis.ContextAuthRecordKey).(*models.Record)
				if loggedAuthRecord != nil && loggedAuthRecord.Collection().Id == collection.Id {
					fallbackAuthRecord = loggedAuthRecord
				}

				form := forms.NewRecordTelegramLogin(p.app, p.options.BotToken, collection, fallbackAuthRecord)
				if readErr := c.Bind(form); readErr != nil {
					return apis.NewBadRequestError("An error occurred while loading the submitted data.", readErr)
				}

				record, authData, submitErr := form.Submit(func(createForm *pbForms.RecordUpsert, authRecord *models.Record, authUser *auth.AuthUser) error {
					return createForm.DrySubmit(func(txDao *daos.Dao) error {
						requestData := apis.RequestData(c)
						requestData.Data = form.CreateData

						createRuleFunc := func(q *dbx.SelectQuery) error {
							admin, _ := c.Get(apis.ContextAdminKey).(*models.Admin)
							if admin != nil {
								return nil // either admin or the rule is empty
							}

							if collection.CreateRule == nil {
								return errors.New("Only admins can create new accounts with OAuth2")
							}

							if *collection.CreateRule != "" {
								resolver := resolvers.NewRecordFieldResolver(txDao, collection, requestData, true)
								if expr, err := search.FilterData(*collection.CreateRule).BuildExpr(resolver); err != nil {
									return err
								} else {
									if updateQueryError := resolver.UpdateQuery(q); updateQueryError != nil {
										return updateQueryError
									}
									q.AndWhere(expr)
								}
							}

							return nil
						}

						if _, err := txDao.FindRecordById(collection.Id, createForm.Id, createRuleFunc); err != nil {
							return fmt.Errorf("Failed create rule constraint: %w", err)
						}

						return nil
					})
				})
				if submitErr != nil {
					return apis.NewBadRequestError("Failed to authenticate.", submitErr)
				}

				return apis.RecordAuthResponse(p.app, c, record, authData)
			},
			Middlewares: []echo.MiddlewareFunc{
				apis.ActivityLogger(app),
			},
		})

		return routeError
	})

	return nil
}
