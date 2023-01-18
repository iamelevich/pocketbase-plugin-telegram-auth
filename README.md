
<!-- TOC -->
  * [Overview](#overview)
    * [Requirements](#requirements)
    * [Installation](#installation)
    * [Example](#example)
    * [Usage](#usage)
  * [Contributing](#contributing)
<!-- TOC -->

## Overview

This plugin implements [Telegram WebApp Auth](https://core.telegram.org/bots/webapps#validating-data-received-via-the-web-app) and [Telegram Login Widget](https://core.telegram.org/widgets/login) for the [pocketbase](https://github.com/pocketbase/pocketbase)

### Requirements

- Go 1.18+
- [Pocketbase](https://github.com/pocketbase/pocketbase) 0.11.3+

### Installation

```bash
go get github.com/iamelevich/pocketbase-plugin-telegram-auth
```

### Example

You can check examples in [examples folder](/examples)

```go
package main

import (
	tgAuthPlugin "github.com/iamelevich/pocketbase-plugin-telegram-auth"
	"log"

	"github.com/pocketbase/pocketbase"
)

func main() {
	app := pocketbase.New()

	// Setup tg auth for users collection
	tgAuthPlugin.MustRegister(app, &tgAuthPlugin.Options{
		BotToken:      "YOUR_SUPER_SECRET_BOT_TOKEN", // Better to use ENV variable for that
		CollectionKey: "users",
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
```

After that new route `POST /api/collections/users/auth-with-telegram` will be available.

### Usage

TODO

## Contributing

This pocketbase plugin is free and open source project licensed under the [MIT License](LICENSE.md).
You are free to do whatever you want with it, even offering it as a paid service.
