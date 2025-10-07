package pocketbase_plugin_telegram_auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

const testDataDir = "./test/test_pb_data"

func TestPlugin_Validate(t *testing.T) {
	type fields struct {
		app     core.App
		options *Options
	}
	scenarios := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Options is nil",
			fields: fields{
				app:     nil,
				options: nil,
			},
			wantErr: true,
		},
		{
			name: "Options is empty",
			fields: fields{
				app:     nil,
				options: &Options{},
			},
			wantErr: true,
		},
		{
			name: "Options BotToken is empty",
			fields: fields{
				app: nil,
				options: &Options{
					BotToken:      "",
					CollectionKey: "users",
				},
			},
			wantErr: true,
		},
		{
			name: "Options CollectionKey is empty",
			fields: fields{
				app: nil,
				options: &Options{
					BotToken:      "BOT_TOKEN",
					CollectionKey: "",
				},
			},
			wantErr: true,
		},
		{
			name: "Options is filled",
			fields: fields{
				app: nil,
				options: &Options{
					BotToken:      "BOT_TOKEN",
					CollectionKey: "users",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range scenarios {
		t.Run(tt.name, func(t *testing.T) {
			p := &Plugin{
				app:     tt.fields.app,
				options: tt.fields.options,
			}
			if err := p.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPlugin_GetCollection(t *testing.T) {
	testApp, err := tests.NewTestApp(testDataDir)
	if err != nil {
		t.Fatal("Cannot initialize test app", err)
	}
	defer testApp.Cleanup()

	type fields struct {
		app        core.App
		options    *Options
		collection *core.Collection
	}
	scenarios := []struct {
		name          string
		fields        fields
		wantErr       bool
		collectionNil bool
	}{
		{
			name: "Collection not exists",
			fields: fields{
				app: testApp,
				options: &Options{
					CollectionKey: "invalid_collection",
				},
			},
			wantErr:       true,
			collectionNil: true,
		},
		{
			name: "Collection stored in plugin",
			fields: fields{
				app: testApp,
				options: &Options{
					CollectionKey: "invalid_collection",
				},
				collection: &core.Collection{},
			},
			wantErr:       false,
			collectionNil: false,
		},
		{
			name: "Collection exists",
			fields: fields{
				app: testApp,
				options: &Options{
					CollectionKey: "users",
				},
			},
			wantErr:       false,
			collectionNil: false,
		},
	}
	for _, tt := range scenarios {
		t.Run(tt.name, func(t *testing.T) {
			p := &Plugin{
				app:        tt.fields.app,
				options:    tt.fields.options,
				collection: tt.fields.collection,
			}
			if collection, err := p.GetCollection(); (err != nil) != tt.wantErr {
				t.Errorf("getCollection() error = %v, wantErr %v", err, tt.wantErr)
			} else if collection == nil && !tt.collectionNil {
				t.Errorf("getCollection() collection is nil")
			}
		})
	}
}

func TestPlugin_GetForm(t *testing.T) {
	testApp, err := tests.NewTestApp(testDataDir)
	if err != nil {
		t.Fatal("Cannot initialize test app", err)
	}
	defer testApp.Cleanup()

	type fields struct {
		app     core.App
		options *Options
	}
	scenarios := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Collection not exists",
			fields: fields{
				app: testApp,
				options: &Options{
					CollectionKey: "invalid_collection",
				},
			},
			wantErr: true,
		},
		{
			name: "Collection not auth",
			fields: fields{
				app: testApp,
				options: &Options{
					CollectionKey: "not_auth_collection",
				},
			},
			wantErr: true,
		},
		{
			name: "Collection is valid",
			fields: fields{
				app: testApp,
				options: &Options{
					CollectionKey: "users",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range scenarios {
		t.Run(tt.name, func(t *testing.T) {
			p := &Plugin{
				app:     tt.fields.app,
				options: tt.fields.options,
			}
			if _, err := p.GetForm(nil); (err != nil) != tt.wantErr {
				t.Errorf("getCollection() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPlugin_MustRegister(t *testing.T) {
	// setup the test ApiScenario app instance
	setupTestApp := func(options *Options) func(testing.TB) *tests.TestApp {
		return func(tb testing.TB) *tests.TestApp {
			testApp, err := tests.NewTestApp(testDataDir)
			if err != nil {
				t.Fatalf("Cannot initialize test app: %v", err)
				return nil
			}

			MustRegister(testApp, options)

			return testApp
		}
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "Collection not exists",
			Method:          http.MethodPost,
			URL:             "/api/collections/invalid_collection/auth-with-telegram",
			ExpectedStatus:  404,
			ExpectedContent: []string{`{"data":{},"message":"Collection not found.","status":404}`},

			TestAppFactory: setupTestApp(&Options{
				CollectionKey: "invalid_collection",
				BotToken:      "test_bot_token",
			}),
		},
		{
			Name:            "Collection not auth type",
			Method:          http.MethodPost,
			URL:             "/api/collections/not_auth_collection/auth-with-telegram",
			ExpectedStatus:  400,
			ExpectedContent: []string{`{"data":{},"message":"Wrong collection type. not_auth_collection should be auth collection.","status":400}`},
			TestAppFactory: setupTestApp(&Options{
				CollectionKey: "not_auth_collection",
				BotToken:      "test_bot_token",
			}),
		},
		{
			Name:            "Data is empty",
			Method:          http.MethodPost,
			URL:             "/api/collections/users/auth-with-telegram",
			ExpectedStatus:  400,
			ExpectedContent: []string{`{"data":{"data":{"code":"validation_required","message":"Cannot be blank."}},"message":"Failed to authenticate.","status":400}`},
			TestAppFactory: setupTestApp(&Options{
				CollectionKey: "users",
				BotToken:      "test_bot_token",
			}),
		},
		{
			Name:   "Valid data user not exists",
			Method: http.MethodPost,
			URL:    "/api/collections/users/auth-with-telegram",
			Body: getBodyFromTgTestData(tgTestData{
				QueryId:  "test_query_id",
				AuthDate: 1,
				User: tgUser{
					Id:           1,
					FirstName:    "test_first_name",
					LastName:     "test_last_name",
					Username:     "test_username",
					LanguageCode: "test_language",
				},
			}, "test_bot_token"),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"id":"1","name":"test_first_name test_last_name","username":"test_username"`},
			ExpectedEvents:  map[string]int{"OnModelAfterCreateSuccess": 3, "OnRecordCreate": 3, "OnRecordAuthRequest": 1},
			TestAppFactory: setupTestApp(&Options{
				CollectionKey: "users",
				BotToken:      "test_bot_token",
			}),
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

type tgTestData struct {
	QueryId  string `json:"query_id"`
	User     tgUser `json:"user"`
	AuthDate int    `json:"auth_date"`
	Hash     string `json:"hash"`
}

type tgUser struct {
	Id           int    `json:"id"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	Username     string `json:"username"`
	LanguageCode string `json:"language_code"`
}

func (u *tgUser) json() string {
	jsonData, _ := json.Marshal(u)
	return string(jsonData)
}

func (u *tgUser) encode() string {
	return url.QueryEscape(u.json())
}

func getBodyFromTgTestData(data tgTestData, botToken string) io.Reader {
	genHash, err := getWebappHash(data, botToken)
	if err != nil {
		panic(err)
	}
	return strings.NewReader(fmt.Sprintf(`{"data": "query_id=%s&user=%s&auth_date=%d&hash=%s"}`, data.QueryId, data.User.encode(), data.AuthDate, genHash))
}

func getWebappHash(data tgTestData, token string) (string, error) {
	strs := []string{
		fmt.Sprintf("auth_date=%d", data.AuthDate),
		fmt.Sprintf("user=%s", data.User.json()),
		fmt.Sprintf("query_id=%s", data.QueryId),
	}

	sort.Strings(strs)

	var imploded = ""
	for _, s := range strs {
		if imploded != "" {
			imploded += "\n"
		}
		imploded += s
	}

	secretKey := hmac.New(sha256.New, []byte("WebAppData"))
	if _, err := io.WriteString(secretKey, token); err != nil {
		return "", err
	}
	resultHash := hmac.New(sha256.New, secretKey.Sum(nil))
	if _, err := io.WriteString(resultHash, imploded); err != nil {
		return "", err
	}
	return hex.EncodeToString(resultHash.Sum(nil)), nil
}
