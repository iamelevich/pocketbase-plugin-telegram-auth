package main

import (
	tgAuthPlugin "github.com/iamelevich/pocketbase-plugin-telegram-auth"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"log"
	"os"

	"github.com/pocketbase/pocketbase"
)

func main() {
	app := pocketbase.New()

	// Setup tg auth for users collection
	tgAuthPlugin.MustRegister(app, &tgAuthPlugin.Options{
		BotToken:      "YOUR_SUPER_SECRET_BOT_TOKEN", // Better to use ENV variable for that
		CollectionKey: "users",
	})

	// Setup serving bundled react app
	app.OnBeforeServe().Add(func(e *core.ServeEvent) error {
		// serves static files from the provided public dir (if exists)
		e.Router.GET("/*", apis.StaticDirectoryHandler(os.DirFS("./tg_webapp/dist"), true))
		return nil
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
