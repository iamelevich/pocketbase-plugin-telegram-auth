
![Coverage](https://img.shields.io/badge/Coverage-38.1%25-yellow)
<!-- TOC -->
  * [Overview](#overview)
    * [Requirements](#requirements)
    * [Installation](#installation)
    * [Autofill fields](#autofill-fields)
    * [Example](#example)
    * [Usage](#usage)
  * [Contributing](#contributing)
<!-- TOC -->

## Overview

This plugin implements [Telegram WebApp Auth](https://core.telegram.org/bots/webapps#validating-data-received-via-the-web-app) and [Telegram Login Widget](https://core.telegram.org/widgets/login) for the [pocketbase](https://github.com/pocketbase/pocketbase)

### Requirements

- Go 1.18+
- [Pocketbase](https://github.com/pocketbase/pocketbase) 0.12+

### Installation

```bash
go get github.com/iamelevich/pocketbase-plugin-telegram-auth
```

### Autofill fields

- `name` - string
- `first_name` - string
- `last_name` - string
- `telegram_username` - string
- `telegram_id` - string
- `language_code` - string

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

Simple usage with js. You can check react example [here](./examples/webapp-react)
```js
const pb = new PocketBase('http://127.0.0.1:8090');
pb.send('/api/collections/users/auth-with-telegram', {
    method: 'POST',
    body: {
        data: window.Telegram.WebApp.initData
    }
}).then(res => {
    pb.authStore.save(res.token, res.record);
});
```

## Contributing

This pocketbase plugin is free and open source project licensed under the [MIT License](LICENSE.md).
You are free to do whatever you want with it, even offering it as a paid service.
