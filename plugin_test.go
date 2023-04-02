package pocketbase_plugin_telegram_auth

import (
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/models"
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
		collection *models.Collection
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
				collection: &models.Collection{},
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
