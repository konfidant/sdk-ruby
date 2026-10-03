# konfidant-ruby

[![Test](https://github.com/konfidant/sdk-ruby/actions/workflows/test.yml/badge.svg)](https://github.com/konfidant/sdk-ruby/actions/workflows/test.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/eb3798f7eb59412abc2bd3ce307760b5)](https://app.codacy.com/gh/konfidant/sdk-ruby/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/eb3798f7eb59412abc2bd3ce307760b5)](https://app.codacy.com/gh/konfidant/sdk-ruby/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)

Official Ruby SDK for the [Konfidant](https://www.konfidant.app) API.

Konfidant lets you share secrets — text and files — that self-destruct after being read.

## Zero-knowledge model

All content is **encrypted on your machine** before anything is sent:

- Every share gets a fresh random 256-bit key. Text, file bytes, file name and MIME type are encrypted together
  with AES-256-GCM in the chunked KNF1
  format (stdlib `OpenSSL` only).
- Konfidant receives only ciphertext and its size. It never sees the key, the content or the file name.
- The key lives **only in the share link's URL fragment**: `https://download.konfidant.app/#t=<token>&k=<key>`.
  Browsers never send the fragment to a server. The `t` token is single-use, so the ciphertext can be fetched once.
- Anyone holding the full `share_url` can read the secret once — treat it like the secret itself. If you lose it,
  the content cannot be recovered by anyone, including Konfidant.

---

## Installation

```ruby
gem 'konfidant'
```

```bash
bundle install   # or: gem install konfidant
```

Requires Ruby >= 3.2. No runtime dependencies (stdlib `net/http`, `openssl`, `json`).

---

## Quick start

```ruby
require 'konfidant'

client = Konfidant::Client.new(api_key: ENV['KONFIDANT_API_KEY'])

text = client.share_text(text: 'db-password: hunter2', ttl_hours: 24)
puts text.share_url

file = File.open('contract.pdf', 'rb') do |f|
  client.share_file(content: f, filename: 'contract.pdf', content_type: 'application/pdf', ttl_hours: 48)
end
puts file.share_url
```

---

## API reference

### `Konfidant::Client.new(api_key:, base_url: nil, http_timeout: 120)`

| Option         | Type      | Required | Description                                                          |
|----------------|-----------|----------|----------------------------------------------------------------------|
| `api_key`      | `String`  | Yes      | Your Konfidant API key (sent as `Authorization: Bearer …`)           |
| `base_url`     | `String`  | No       | Override the API base URL (default: `https://www.konfidant.app`)     |
| `http_timeout` | `Integer` | No       | Per-request HTTP timeout in seconds (default: `120`; `nil` disables) |

Raises `ArgumentError` if `api_key` is nil or empty.

### `client.share_text(text:, ttl_hours: nil)` → `Konfidant::TextShare`

Encrypts `text` (UTF-8, no SDK-side size limit; your plan's limit applies server-side) and uploads the ciphertext.
`ttl_hours` is omitted from the request when `nil` (server default applies).

| Field        | Type          | Description                                    |
|--------------|---------------|------------------------------------------------|
| `share_url`  | `String`      | One-time link **including the key** (`&k=…`)   |
| `text_id`    | `String, nil` | Text ID (`nil` when verified burn is disabled) |
| `expires_at` | `String`      | ISO 8601 expiry                                |

### `client.share_file(content:, filename:, content_type: '', ttl_hours: nil)` → `Konfidant::FileShare`

Encrypts and shares a file in one call: encrypt → `create_file_upload` → `upload_ciphertext` → `complete_file_upload`.

| Argument       | Type         | Description                                                                         |
|----------------|--------------|-------------------------------------------------------------------------------------|
| `content`      | `String, IO` | File bytes, or a readable IO. `File`/`StringIO` are streamed chunk by chunk; other IOs are read into memory |
| `filename`     | `String`     | Original file name, at most 1 024 UTF-8 bytes (encrypted)                           |
| `content_type` | `String`     | MIME type, at most 255 bytes, may be empty (encrypted)                              |
| `ttl_hours`    | `Integer`    | Time-to-live in hours (optional)                                                    |

| Field           | Type          | Description                                  |
|-----------------|---------------|----------------------------------------------|
| `share_url`     | `String`      | One-time link **including the key** (`&k=…`) |
| `file_id`       | `String, nil` | File ID (`nil` when verified burn is off)    |
| `expires_at`    | `String`      | ISO 8601 expiry                              |
| `verified_burn` | `Boolean`     | Whether verified burn is enabled             |

### Low-level file flow

Use these when you need control over each step (e.g. your own retry logic).

```ruby
key       = Konfidant::Knf.generate_key
encryptor = Konfidant::Knf.encryptor(key: key, content: File.open('a.zip', 'rb'), kind: 'file',
                                     name: 'a.zip', mime: 'application/zip')

upload = client.create_file_upload(ciphertext_size: encryptor.size, ttl_hours: 24)
client.upload_ciphertext(upload: upload, ciphertext: encryptor)   # String or IO-like
done   = client.complete_file_upload(file_key: upload.file_key)

share_url = Konfidant::Knf.build_share_url(done.download_url, key)
```

| Method                                              | Request                                          | Returns                                                                                 |
|-----------------------------------------------------|--------------------------------------------------|-----------------------------------------------------------------------------------------|
| `create_file_upload(ciphertext_size:, ttl_hours:)`  | `POST /api/v1/files`                             | `FileUpload(upload_url, file_key, upload_headers, upload_expires_in, ciphertext_size)` |
| `upload_ciphertext(upload:, ciphertext:)`           | `PUT upload_url` with exactly `upload_headers`   | `nil`; never sends the API key                                                          |
| `complete_file_upload(file_key:)`                   | `POST /api/v1/files/{file_key}/complete`         | `CompletedUpload(download_url, file_id, expires_at, verified_burn)`                    |

`complete_file_upload` raises `ApiError` with status `409` and message `upload_incomplete` if the PUT did not land.
`download_url` contains only the token — append the key with `Knf.build_share_url` before sending it to anyone.

### `client.open_share(share_url)` → `Konfidant::OpenedShare`

Recipient side. Sends only the token (`POST https://<link host>/api/download`, no API key, no decryption key),
receives the ciphertext and decrypts it locally. Opening a share **consumes it**.

| Field  | Type          | Description                                 |
|--------|---------------|---------------------------------------------|
| `kind` | `String`      | `"text"` or `"file"`                        |
| `name` | `String`      | File name (`""` for text)                   |
| `mime` | `String`      | MIME type (`""` for text)                   |
| `data` | `String`      | Decrypted bytes (binary / ASCII-8BIT)       |
| `text` | `String, nil` | UTF-8 text for text shares, otherwise `nil` |

Raises `ApiError` (`410`) if the share was already opened or has expired, `KnfError` if the ciphertext does not
authenticate (wrong key, modified or truncated data).

### `client.list_shares(type: nil, status: nil, limit: nil, offset: nil)` → `Konfidant::ListSharesResponse`

| Argument | Type      | Description                |
|----------|-----------|----------------------------|
| `type`   | `String`  | `"file"` or `"text"`       |
| `status` | `String`  | `"active"` or `"accessed"` |
| `limit`  | `Integer` | Page size (default 50)     |
| `offset` | `Integer` | Pagination offset          |

Returns `shares` (`Array<Konfidant::Share>` with `type`, `file_size_bytes`, `created_at`, `expires_at`,
`accessed_at`, `created_by`) and `pagination` (`total`, `limit`, `offset`, `has_more`). File names are not
available: the server never sees them.

### `Konfidant::Knf`

The KNF1 implementation is public for advanced use and interoperability:

| Method                                                                 | Description                                         |
|------------------------------------------------------------------------|-----------------------------------------------------|
| `generate_key` / `encode_key(key)` / `decode_key(str)`                 | 32-byte key; unpadded base64url (43 chars)          |
| `encrypt(key:, content:, kind:, name: '', mime: '')`                   | Full ciphertext as a binary String                  |
| `encryptor(...)`                                                       | Streaming IO-like encryptor (`#read`, `#size`)      |
| `encrypt_text(key:, text:)`                                            | Text share ciphertext                               |
| `decrypt(key:, ciphertext:)` / `Decryptor.new(key:)#push`/`#finish`    | Verify and decrypt (one-shot or streaming)          |
| `ciphertext_size(metadata_length:, content_length:)`                   | Exact ciphertext length                             |
| `build_share_url(download_url, key)` / `parse_share_url(url)`          | Share link helpers                                  |

`encrypt` also accepts `chunk_size:` and a `nonce_prefix:` option that exists **only** for reproducing test
vectors — never pass `nonce_prefix` in production.

---

## Error handling

All SDK errors inherit from `Konfidant::Error`.

```ruby
begin
  client.share_text(text: 'secret', ttl_hours: 1)
rescue Konfidant::ApiError => e
  e.message      # the "error" field of the JSON body, e.g. "upload_incomplete", or "HTTP 500"
  e.status_code  # e.g. 401
  e.body         # parsed body (Hash) or raw String
rescue Konfidant::KnfError => e
  e.message      # encryption/decryption failure
end
```

| Status | Meaning                                   |
|--------|-------------------------------------------|
| `400`  | Bad request / invalid body                |
| `401`  | Missing or invalid API key                |
| `403`  | Insufficient API key scope                |
| `404`  | Resource not found                        |
| `409`  | `upload_incomplete` on complete           |
| `410`  | Share already opened or expired           |

---

## Development

```bash
bundle install
bundle exec rspec
```

`spec/fixtures/knf1-test-vectors.json` holds the cross-SDK KNF1 test vectors; the specs reproduce every ciphertext
byte for byte.
