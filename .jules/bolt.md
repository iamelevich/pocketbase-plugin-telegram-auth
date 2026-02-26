## 2026-02-25 - [Redundant Query Parsing]
**Learning:** The RecordTelegramLogin form was parsing the Telegram initData query string multiple times during a single request (once for authorization validation and once for user data extraction). This led to redundant CPU cycles and memory allocations.
**Action:** Cache the parsed url.Values in the form struct after the first parse to reuse across validation and submission methods.
