## 2026-02-25 - [Redundant Query Parsing]
**Learning:** The RecordTelegramLogin form was parsing the Telegram initData query string multiple times during a single request (once for authorization validation and once for user data extraction). This led to redundant CPU cycles and memory allocations.
**Action:** Cache the parsed url.Values in the form struct after the first parse to reuse across validation and submission methods.

## 2026-02-25 - [Modern Go Sorting and Constant-Time Comparison]
**Learning:** Replacing `sort.Strings` with generic `slices.SortFunc` (Go 1.21+) reduces interface overhead during sorting. Additionally, using `hmac.Equal` with hex-decoded bytes for hash comparison provides a constant-time check, which is a security best practice for cryptographic signatures.
**Action:** Use `slices.SortFunc` for performance-critical sorting and `hmac.Equal` for hash verification.

## 2025-02-25 - [Allocation Reduction in Hashing Hot Path]
**Learning:** Using `h.Write([]byte(s))` instead of `io.WriteString(h, s)` allows the Go compiler to optimize away string-to-slice allocations. Combining this with stack-allocated buffers for `hex.Decode` (with proper length validation) significantly reduces heap pressure in the authentication hot path.
**Action:** Prefer direct `Write([]byte(s))` for hashes and stack-allocated buffers for fixed-size cryptographic outputs.
