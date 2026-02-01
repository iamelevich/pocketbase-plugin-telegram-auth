package pocketbase_plugin_telegram_auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/iamelevich/pocketbase-plugin-telegram-auth/forms"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/auth"
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
	setupTestApp := func(options *Options) func(t testing.TB) *tests.TestApp {
		return func(t testing.TB) *tests.TestApp {
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
			ExpectedContent: []string{`"name":"test_first_name test_last_name"`, `"username":"test_username"`},
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

func TestRegister(t *testing.T) {
	t.Run("nil options returns error", func(t *testing.T) {
		testApp, err := tests.NewTestApp(testDataDir)
		if err != nil {
			t.Fatal("Cannot initialize test app", err)
		}
		defer testApp.Cleanup()

		p, err := Register(testApp, nil)
		if err == nil {
			t.Error("Register(nil) expected error, got nil")
		}
		if p == nil {
			t.Error("Register(nil) should return plugin even on error")
		}
	})

	t.Run("invalid options returns error", func(t *testing.T) {
		testApp, err := tests.NewTestApp(testDataDir)
		if err != nil {
			t.Fatal("Cannot initialize test app", err)
		}
		defer testApp.Cleanup()

		p, err := Register(testApp, &Options{
			BotToken:      "",
			CollectionKey: "users",
		})
		if err == nil {
			t.Error("Register with empty BotToken expected error, got nil")
		}
		if p == nil {
			t.Error("Register should return plugin even on validation error")
		}
	})

	t.Run("valid options succeeds", func(t *testing.T) {
		testApp, err := tests.NewTestApp(testDataDir)
		if err != nil {
			t.Fatal("Cannot initialize test app", err)
		}
		defer testApp.Cleanup()

		p, err := Register(testApp, &Options{
			BotToken:      "test_bot_token",
			CollectionKey: "users",
		})
		if err != nil {
			t.Errorf("Register with valid options: unexpected error %v", err)
		}
		if p == nil {
			t.Error("Register should return plugin on success")
		}
	})
}

func TestMustRegister_panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustRegister with invalid options should panic")
		}
	}()

	testApp, err := tests.NewTestApp(testDataDir)
	if err != nil {
		t.Fatal("Cannot initialize test app", err)
	}
	defer testApp.Cleanup()

	MustRegister(testApp, &Options{
		BotToken:      "",
		CollectionKey: "users",
	})
}

func TestAuthByTelegramData(t *testing.T) {
	testApp, err := tests.NewTestApp(testDataDir)
	if err != nil {
		t.Fatal("Cannot initialize test app", err)
	}
	defer testApp.Cleanup()

	p, err := Register(testApp, &Options{
		BotToken:      "test_bot_token",
		CollectionKey: "users",
	})
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	t.Run("success creates new user", func(t *testing.T) {
		tgData := forms.TelegramData{
			Id:           999,
			FirstName:    "AuthFirst",
			LastName:     "AuthLast",
			Username:     "auth_user",
			LanguageCode: "en",
		}
		record, authUser, err := p.AuthByTelegramData(tgData)
		if err != nil {
			t.Fatalf("AuthByTelegramData: unexpected error %v", err)
		}
		if record == nil {
			t.Fatal("AuthByTelegramData: expected record, got nil")
		}
		if authUser == nil {
			t.Fatal("AuthByTelegramData: expected authUser, got nil")
		}
		if authUser.Id != "999" {
			t.Errorf("AuthByTelegramData: expected authUser.Id=999, got %s", authUser.Id)
		}
		if authUser.Name != "AuthFirst AuthLast" {
			t.Errorf("AuthByTelegramData: expected authUser.Name='AuthFirst AuthLast', got %s", authUser.Name)
		}
	})

	t.Run("invalid collection returns error", func(t *testing.T) {
		pInvalid, _ := Register(testApp, &Options{
			BotToken:      "test_bot_token",
			CollectionKey: "invalid_collection",
		})
		tgData := forms.TelegramData{Id: 1, FirstName: "Test"}
		_, _, err := pInvalid.AuthByTelegramData(tgData)
		if err == nil {
			t.Error("AuthByTelegramData with invalid collection expected error, got nil")
		}
	})
}

func TestTelegramProvider_FetchAuthUser(t *testing.T) {
	testApp, err := tests.NewTestApp(testDataDir)
	if err != nil {
		t.Fatal("Cannot initialize test app", err)
	}
	defer testApp.Cleanup()

	_, _ = Register(testApp, &Options{
		BotToken:      "test_bot_token",
		CollectionKey: "users",
	})

	providerFn, ok := auth.Providers["telegram"]
	if !ok {
		t.Fatal("telegram provider not registered")
	}
	provider := providerFn()
	_, err = provider.FetchAuthUser(nil)
	if err == nil {
		t.Error("FetchAuthUser expected to return error for custom flow")
	}
	if err != nil && !strings.Contains(err.Error(), "custom flow") {
		t.Errorf("FetchAuthUser error should mention custom flow, got: %v", err)
	}
}

func TestMustRegister_ApiScenarios_EdgeCases(t *testing.T) {
	setupTestApp := func(options *Options) func(t testing.TB) *tests.TestApp {
		return func(t testing.TB) *tests.TestApp {
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
			Name:            "Invalid hash returns 400",
			Method:          http.MethodPost,
			URL:             "/api/collections/users/auth-with-telegram",
			Body:            strings.NewReader(`{"data":"query_id=id&user=%7B%22id%22%3A1%7D&auth_date=1&hash=invalid_hash"}`),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"message":"Failed to authenticate."`},
			TestAppFactory: setupTestApp(&Options{
				CollectionKey: "users",
				BotToken:      "test_bot_token",
			}),
		},
		{
			Name:            "Invalid JSON body returns 400",
			Method:          http.MethodPost,
			URL:             "/api/collections/users/auth-with-telegram",
			Body:            strings.NewReader(`{invalid json`),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"message":"Failed to read request data.`},
			TestAppFactory: setupTestApp(&Options{
				CollectionKey: "users",
				BotToken:      "test_bot_token",
			}),
		},
		{
			Name:   "Create user with different telegram id",
			Method: http.MethodPost,
			URL:    "/api/collections/users/auth-with-telegram",
			Body: getBodyFromTgTestData(tgTestData{
				QueryId:  "query_1",
				AuthDate: 100,
				User: tgUser{
					Id:           91929182,
					FirstName:    "Another",
					LastName:     "User",
					Username:     "another_user",
					LanguageCode: "en",
				},
			}, "test_bot_token"),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"name":"Another User"`, `"username":"another_user"`},
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

func TestAuthWithTelegram_ExistingUserReturnsSameRecord(t *testing.T) {
	// Use TempDirClone for fresh data to ensure no pre-existing user with our telegram id
	cleanDataDir, err := tests.TempDirClone(testDataDir)
	if err != nil {
		t.Fatalf("Failed to clone test data: %v", err)
	}
	// cleanDataDir becomes the TestApp's DataDir; Cleanup() will remove it
	testApp, err := tests.NewTestApp(cleanDataDir)
	if err != nil {
		t.Fatal("Cannot initialize test app", err)
	}
	defer testApp.Cleanup()

	MustRegister(testApp, &Options{
		CollectionKey: "users",
		BotToken:      "test_bot_token",
	})

	baseRouter, err := apis.NewRouter(testApp)
	if err != nil {
		t.Fatal(err)
	}
	serveEvent := &core.ServeEvent{App: testApp, Router: baseRouter}
	if err := testApp.OnServe().Trigger(serveEvent, func(e *core.ServeEvent) error {
		mux, err := e.Router.BuildMux()
		if err != nil {
			t.Fatal(err)
		}

		doRequest := func(body io.Reader) *http.Response {
			req := httptest.NewRequest(http.MethodPost, "/api/collections/users/auth-with-telegram", body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			return rec.Result()
		}

		// Use unique telegram id to avoid collision with any pre-seeded data
		tgID := 838475619
		body1 := getBodyFromTgTestData(tgTestData{
			QueryId:  "existing_user_query",
			AuthDate: 200,
			User: tgUser{
				Id:           tgID,
				FirstName:    "Returning",
				LastName:     "User",
				Username:     "returning_user",
				LanguageCode: "en",
			},
		}, "test_bot_token")
		res1 := doRequest(body1)
		defer func() {
			if err := res1.Body.Close(); err != nil {
				t.Fatalf("Failed to close response body: %v", err)
			}
		}()
		body1Bytes, _ := io.ReadAll(res1.Body)
		if res1.StatusCode != http.StatusOK {
			t.Fatalf("First request failed: status=%d, body=%s", res1.StatusCode, string(body1Bytes))
		}
		// Extract record ID from first response
		var resp1 struct {
			Record struct {
				Id string `json:"id"`
			} `json:"record"`
		}
		if err := json.Unmarshal(body1Bytes, &resp1); err != nil {
			t.Fatalf("Failed to parse first response: %v", err)
		}
		firstRecordID := resp1.Record.Id
		if firstRecordID == "" {
			t.Fatal("First request should return record with id")
		}

		body2 := getBodyFromTgTestData(tgTestData{
			QueryId:  "existing_user_query_2",
			AuthDate: 201,
			User: tgUser{
				Id:           tgID,
				FirstName:    "Returning",
				LastName:     "User",
				Username:     "returning_user",
				LanguageCode: "en",
			},
		}, "test_bot_token")
		res2 := doRequest(body2)
		defer func() {
			if err := res2.Body.Close(); err != nil {
				t.Fatalf("Failed to close response body: %v", err)
			}
		}()
		body2Bytes, _ := io.ReadAll(res2.Body)
		if res2.StatusCode != http.StatusOK {
			t.Fatalf("Second request failed: status=%d, body=%s", res2.StatusCode, string(body2Bytes))
		}
		var resp2 struct {
			Record struct {
				Id string `json:"id"`
			} `json:"record"`
		}
		if err := json.Unmarshal(body2Bytes, &resp2); err != nil {
			t.Fatalf("Failed to parse second response: %v", err)
		}
		if resp2.Record.Id != firstRecordID {
			t.Errorf("Second request should return same record (id=%s), got id=%s", firstRecordID, resp2.Record.Id)
		}
		return nil
	}); err != nil {
		t.Fatalf("Failed to trigger serve: %v", err)
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
