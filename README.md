# konfidant-ruby

[![Test](https://github.com/konfidant/sdk-ruby/actions/workflows/test.yml/badge.svg)](https://github.com/konfidant/sdk-ruby/actions/workflows/test.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/eb3798f7eb59412abc2bd3ce307760b5)](https://app.codacy.com/gh/konfidant/sdk-ruby/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/eb3798f7eb59412abc2bd3ce307760b5)](https://app.codacy.com/gh/konfidant/sdk-ruby/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)

Official Ruby SDK for the [Konfidant](https://www.konfidant.app) API.

Konfidant lets you share secrets — encrypted text and files — that self-destruct after being read.

---

## Installation

Add to your `Gemfile`:

```ruby
gem 'konfidant'
```

Then run:

```bash
bundle install
```

Or install directly:

```bash
gem install konfidant
```

---

## Quick start

```ruby
require 'konfidant'

client = Konfidant::Client.new(api_key: 'your-api-key')

result = client.share_text(text: 'super-secret-password', ttl_hours: 24)

puts "Share this link: #{result.share_url}"
```

---

## Authentication

All requests require a Bearer API key. Generate one from the [Konfidant dashboard](https://www.konfidant.app).

```ruby
client = Konfidant::Client.new(api_key: ENV['KONFIDANT_API_KEY'])
```

---

## API Reference

### `Konfidant::Client.new`

| Option         | Type      | Required | Description                                                          |
|----------------|-----------|----------|----------------------------------------------------------------------|
| `api_key`      | `String`  | Yes      | Your Konfidant API key                                               |
| `base_url`     | `String`  | No       | Override the base URL (default: `https://www.konfidant.app`)         |
| `http_timeout` | `Integer` | No       | Per-request HTTP timeout in seconds (default: `120`; `nil` disables) |

Raises `ArgumentError` if `api_key` is nil or empty.

---

### `client.share_text(text:, ttl_hours:)`

Encrypt and share a text message.

| Argument    | Type      | Description              |
|-------------|-----------|--------------------------|
| `text`      | `String`  | The secret text to share |
| `ttl_hours` | `Integer` | Time-to-live in hours    |

Returns a `Konfidant::ShareTextResponse`:

| Field          | Type      | Description                                 |
|----------------|-----------|---------------------------------------------|
| `text_id`      | `String`  | Unique ID of the shared text                |
| `share_url`    | `String`  | One-time download link to send to recipient |
| `expires_at`   | `String`  | Expiry datetime                             |
| `verified_burn`| `Boolean` | Whether burn-on-read is verified            |

#### Example: share text

```ruby
result = client.share_text(text: 'db-password: hunter2', ttl_hours: 48)

puts result.share_url    # send to recipient
puts result.expires_at
puts result.verified_burn
```

---

### `client.share_file(filename:, file_size:, ttl_hours:)`

Request a presigned upload URL for a file. Use the returned response with `upload_file` to complete
the upload, then poll `get_file_status` for the share link.

> For a one-call convenience wrapper, see [`share_and_upload_file`](#clientshare_and_upload_file).

| Argument    | Type      | Description                      |
|-------------|-----------|----------------------------------|
| `filename`  | `String`  | Original filename with extension |
| `file_size` | `Integer` | File size in bytes               |
| `ttl_hours` | `Integer` | Time-to-live in hours            |

Returns a `Konfidant::ShareFileResponse`:

| Field              | Type                          | Description                                     |
|--------------------|-------------------------------|-------------------------------------------------|
| `upload_url`       | `String`                      | Short-lived presigned S3 PUT URL                |
| `file_key`         | `String`                      | Use with `get_file_status` and `upload_file`    |
| `poll_url`         | `String`                      | Convenience URL for status polling              |
| `metadata_headers` | `Konfidant::FileMetadataHeaders` | Required S3 headers — passed by `upload_file` |

---

### `client.upload_file(io:, size:, content_type:, presigned:)`

Upload file bytes to the presigned S3 URL from `share_file`. Automatically attaches the required
S3 metadata headers. Does **not** send the Konfidant `Authorization` header to S3.

| Argument       | Type                        | Description                           |
|----------------|-----------------------------|---------------------------------------|
| `io`           | `IO`                        | Readable IO object (File, StringIO)   |
| `size`         | `Integer`                   | Content-Length in bytes               |
| `content_type` | `String`                    | MIME type (e.g. `application/pdf`)    |
| `presigned`    | `Konfidant::ShareFileResponse` | Full response from `share_file`    |

Returns `nil` on success. Raises `Konfidant::ApiError` on S3 error.

#### Example: manual three-step flow

```ruby
file = File.open('report.pdf', 'rb')
size = File.size('report.pdf')

# Step 1 – get presigned URL
presigned = client.share_file(
  filename:  'report.pdf',
  file_size: size,
  ttl_hours: 72
)

# Step 2 – upload to S3
client.upload_file(
  io:           file,
  size:         size,
  content_type: 'application/pdf',
  presigned:    presigned
)

# Step 3 – poll for share link
loop do
  status = client.get_file_status(presigned.file_key)
  if status.status == 'complete'
    puts "Share URL: #{status.share_url}"
    break
  end
  sleep 2
end
```

---

### `client.get_file_status(file_key)`

Poll the encryption status of an uploaded file.

| Argument   | Type     | Description                                   |
|------------|----------|-----------------------------------------------|
| `file_key` | `String` | The `file_key` from the `share_file` response |

Returns a `Konfidant::FileStatusResponse`:

| Field          | Type      | When set                                |
|----------------|-----------|-----------------------------------------|
| `status`       | `String`  | Always (`"processing"` or `"complete"`) |
| `message`      | `String`  | When `processing`                       |
| `file_id`      | `String`  | When `complete`                         |
| `file_name`    | `String`  | When `complete`                         |
| `share_url`    | `String`  | When `complete`                         |
| `expires_at`   | `String`  | When `complete`                         |
| `verified_burn`| `Boolean` | When `complete`                         |

---

### `client.list_shares(type: nil, status: nil, limit: nil, offset: nil)`

List all shares for the authenticated organization. All parameters are optional.

| Argument | Type     | Description                    |
|----------|----------|--------------------------------|
| `type`   | `String` | `"file"` or `"text"`           |
| `status` | `String` | `"active"` or `"accessed"`     |
| `limit`  | `Integer`| Page size (default 50)         |
| `offset` | `Integer`| Pagination offset              |

Returns a `Konfidant::ListSharesResponse`:

| Field        | Type                       | Description         |
|--------------|----------------------------|---------------------|
| `shares`     | `Array<Konfidant::Share>`  | Share entries       |
| `pagination` | `Konfidant::Pagination`    | Page metadata       |

Each `Konfidant::Share`:

| Field            | Type          | Description             |
|------------------|---------------|-------------------------|
| `type`           | `String`      | `"file"` or `"text"`    |
| `file_name`      | `String`      | Filename or text label  |
| `file_size_bytes`| `Integer`     | Size in bytes           |
| `created_at`     | `String`      | Creation datetime       |
| `expires_at`     | `String`      | Expiry datetime         |
| `accessed_at`    | `String, nil` | Access datetime, or nil |
| `created_by`     | `String`      | Email of creator        |

`Konfidant::Pagination`:

| Field      | Type      | Description              |
|------------|-----------|--------------------------|
| `total`    | `Integer` | Total number of shares   |
| `limit`    | `Integer` | Page size used           |
| `offset`   | `Integer` | Offset used              |
| `has_more` | `Boolean` | Whether more pages exist |

#### Example: list shares

```ruby
result = client.list_shares(type: 'file', limit: 10)

result.shares.each do |share|
  puts "#{share.file_name} — expires #{share.expires_at}"
end

puts "Total: #{result.pagination.total}"
puts "More? #{result.pagination.has_more}"
```

---

### `client.share_and_upload_file`

Convenience wrapper that calls `share_file` → `upload_file` → polls `get_file_status` until complete.

```ruby
client.share_and_upload_file(
  io:            io,
  size:          size,
  filename:      filename,
  content_type:  content_type,
  ttl_hours:     ttl_hours,
  poll_interval: 2,   # seconds between status checks (default: 2)
  timeout:       60   # max wait for encryption in seconds (default: 60)
)
```

| Argument        | Type      | Default | Description                         |
|-----------------|-----------|---------|-------------------------------------|
| `io`            | `IO`      | —       | Readable IO object (File, StringIO) |
| `size`          | `Integer` | —       | File size in bytes                  |
| `filename`      | `String`  | —       | Filename with extension             |
| `content_type`  | `String`  | —       | MIME type                           |
| `ttl_hours`     | `Integer` | —       | Time-to-live in hours               |
| `poll_interval` | `Numeric` | `2`     | Seconds between status checks       |
| `timeout`       | `Numeric` | `60`    | Max seconds to wait for encryption  |

Returns a `Konfidant::ShareResult`:

| Field          | Type      | Description                    |
|----------------|-----------|--------------------------------|
| `share_url`    | `String`  | One-time download link         |
| `file_id`      | `String`  | Unique file ID                 |
| `expires_at`   | `String`  | Expiry datetime                |
| `verified_burn`| `Boolean` | Whether burn-on-read is active |

Raises `RuntimeError` with `"konfidant: encryption timed out after Ns"` if encryption does not complete
within `timeout` seconds.

#### Example: share and upload file

```ruby
file = File.open('confidential.zip', 'rb')
size = File.size('confidential.zip')

result = client.share_and_upload_file(
  io:           file,
  size:         size,
  filename:     'confidential.zip',
  content_type: 'application/zip',
  ttl_hours:    48
)

puts "Ready to share: #{result.share_url}"
```

---

## Error handling

All API and S3 errors raise `Konfidant::ApiError`.

```ruby
begin
  client.share_text(text: 'secret', ttl_hours: 1)
rescue Konfidant::ApiError => e
  puts e.message     # e.g. "Missing or invalid Authorization header."
  puts e.status_code # e.g. 401
  puts e.body.inspect # parsed response body (Hash or String)
end
```

### Common error codes

| Status | Meaning                    |
|--------|----------------------------|
| `400`  | Bad request / invalid body |
| `401`  | Missing or invalid API key |
| `403`  | Insufficient API key scope |
| `404`  | Resource not found         |

---

## Development

```bash
bundle install    # install dependencies
bundle exec rspec # run tests
```

### Requirements

- Ruby >= 3.2.0
- No runtime dependencies (uses stdlib `net/http`, `uri`, `json`)
