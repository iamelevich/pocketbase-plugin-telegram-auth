package forms

import (
	"testing"

	"github.com/pocketbase/pocketbase/tests"
)

func BenchmarkCheckTelegramAuthorization(b *testing.B) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	authCollection, _ := app.FindCollectionByNameOrId("users")
	form := NewRecordTelegramLogin(app, "test", authCollection, nil)
	data := "query_id=AAGSTRQLAAAAAJJNFAsbizs2&user=%7B%22id%22%3A185879954%2C%22first_name%22%3A%22Ilya%22%2C%22last_name%22%3A%22%22%2C%22username%22%3A%22beer13%22%2C%22language_code%22%3A%22ru%22%7D&auth_date=1673317539&hash=74e1b67c230d2343f5d317a4d77841e9c673cae1bde28606a40825a98c7be638"
	form.Data = data

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = form.checkTelegramAuthorization(data)
	}
}
