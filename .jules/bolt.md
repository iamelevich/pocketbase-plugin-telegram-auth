## 2026-02-25 - [Redundant Query Parsing]
**Learning:** The RecordTelegramLogin form was parsing the Telegram initData query string multiple times during a single request (once for authorization validation and once for user data extraction). This led to redundant CPU cycles and memory allocations.
**Action:** Cache the parsed url.Values in the form struct after the first parse to reuse across validation and submission methods.

## 2026-02-26 - [Authorization Check Optimization]
**Learning:** Iterating over map keys, sorting them, and then performing individual map lookups for values creates unnecessary overhead. Hex-encoding hash results for comparison also adds allocation and CPU costs.
**Action:** Collect key-value pairs into a slice of structs for a single-pass processing. Use `slices.SortFunc` for efficient sorting and `hmac.Equal` with decoded bytes for constant-time, more efficient verification.
