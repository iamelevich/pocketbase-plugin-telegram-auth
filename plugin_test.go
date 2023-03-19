package pocketbase_plugin_telegram_auth

import (
	"testing"

	"github.com/pocketbase/pocketbase/core"
)

func TestPlugin_Validate(t *testing.T) {
	type fields struct {
		app     core.App
		options *Options
	}
	tests := []struct {
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
	for _, tt := range tests {
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
