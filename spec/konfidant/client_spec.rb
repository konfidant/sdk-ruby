RSpec.describe Konfidant::Client do
  let(:base_url)     { 'http://api.test' }
  let(:client)       { described_class.new(api_key: 'test-key', base_url: base_url) }
  let(:json_ct)      { { 'Content-Type' => 'application/json' } }
  let(:upload_url)   { 'http://storage.test/bucket/abc123?X-Amz-Signature=sig' }
  let(:download_url) { 'https://download.konfidant.app/#t=tok%2Ben' }
  let(:upload_headers) do
    { 'Content-Type' => 'application/octet-stream', 'x-amz-meta-organization-id' => 'org-1' }
  end
  let(:empty_list) do
    { 'shares' => [], 'pagination' => { 'total' => 0, 'limit' => 50, 'offset' => 0, 'has_more' => false } }
  end

  def stub_api(method, path, status:, body:)
    stub_request(method, "#{base_url}#{path}")
      .to_return(status: status, body: body.to_json, headers: json_ct)
  end

  def upload_response(file_key: 'abc123')
    { 'upload_url' => upload_url, 'file_key' => file_key, 'upload_headers' => upload_headers,
      'upload_expires_in' => 900 }
  end

  def complete_response
    { 'download_url' => download_url, 'file_id' => 'file-1', 'expires_at' => '2026-10-05T00:00:00Z',
      'verified_burn' => true }
  end

  def key_from(share_url)
    Konfidant::Knf.decode_key(share_url[/&k=([A-Za-z0-9_-]{43})\z/, 1])
  end

  # ---------------------------------------------------------------------------
  # Constructor
  # ---------------------------------------------------------------------------

  describe '.new' do
    it 'raises when api_key is empty' do
      expect { described_class.new(api_key: '') }.to raise_error(ArgumentError, 'api_key is required')
    end

    it 'raises when api_key is nil' do
      expect { described_class.new(api_key: nil) }.to raise_error(ArgumentError, 'api_key is required')
    end

    it 'strips trailing slash from base_url' do
      c = described_class.new(api_key: 'k', base_url: 'https://example.com/')
      stub_request(:get, 'https://example.com/api/v1/shares')
        .to_return(status: 200, body: empty_list.to_json, headers: json_ct)
      expect { c.list_shares }.not_to raise_error
    end

    it 'defaults to production base URL' do
      c = described_class.new(api_key: 'k')
      stub_request(:get, 'https://www.konfidant.app/api/v1/shares')
        .to_return(status: 200, body: empty_list.to_json, headers: json_ct)
      expect { c.list_shares }.not_to raise_error
    end

    it 'accepts nil http_timeout to disable timeout' do
      c = described_class.new(api_key: 'k', base_url: base_url, http_timeout: nil)
      stub_api(:get, '/api/v1/shares', status: 200, body: empty_list)
      expect { c.list_shares }.not_to raise_error
    end
  end

  # ---------------------------------------------------------------------------
  # share_text
  # ---------------------------------------------------------------------------

  describe '#share_text' do
    let(:text_response) do
      { 'download_url' => download_url, 'text_id' => 'txt-1', 'expires_at' => '2026-10-05T00:00:00Z' }
    end

    it 'sends only KNF1 ciphertext (standard base64) with auth and ttl' do
      sent = nil
      stub_request(:post, "#{base_url}/api/v1/texts")
        .with(headers: { 'Authorization' => 'Bearer test-key', 'Content-Type' => 'application/json' })
        .with { |req| sent = JSON.parse(req.body) }
        .to_return(status: 201, body: text_response.to_json, headers: json_ct)

      result = client.share_text(text: 'db-password: hunter2', ttl_hours: 48)

      expect(sent.keys).to contain_exactly('ciphertext', 'ttl_hours')
      expect(sent['ttl_hours']).to eq(48)
      expect(sent['ciphertext']).to match(%r{\A[A-Za-z0-9+/]+=*\z})
      ciphertext = sent['ciphertext'].unpack1('m0')
      expect(ciphertext).to start_with('KNF1')
      expect(ciphertext).not_to include('hunter2')
      expect(Konfidant::Knf.decrypt(key: key_from(result.share_url), ciphertext: ciphertext).text)
        .to eq('db-password: hunter2')
    end

    it 'returns a TextShare whose share_url carries the key in the fragment' do
      stub_api(:post, '/api/v1/texts', status: 201, body: text_response)
      result = client.share_text(text: 'secret')

      expect(result).to be_a(Konfidant::TextShare)
      expect(result.share_url).to match(%r{\Ahttps://download\.konfidant\.app/#t=tok%2Ben&k=[A-Za-z0-9_-]{43}\z})
      expect(result.text_id).to eq('txt-1')
      expect(result.expires_at).to eq('2026-10-05T00:00:00Z')
    end

    it 'never sends the key to the server' do
      sent = nil
      stub_request(:post, "#{base_url}/api/v1/texts")
        .with { |req| sent = req.body }
        .to_return(status: 201, body: text_response.to_json, headers: json_ct)
      result = client.share_text(text: 'secret')
      encoded_key = result.share_url.split('&k=').last
      expect(sent).not_to include(encoded_key)
      expect(sent).not_to include(encoded_key.tr('-_', '+/'))
    end

    it 'omits ttl_hours when not given' do
      stub_request(:post, "#{base_url}/api/v1/texts")
        .with { |req| !JSON.parse(req.body).key?('ttl_hours') }
        .to_return(status: 201, body: text_response.to_json, headers: json_ct)
      expect { client.share_text(text: 'x') }.not_to raise_error
    end

    it 'accepts a null text_id' do
      stub_api(:post, '/api/v1/texts', status: 201, body: text_response.merge('text_id' => nil))
      expect(client.share_text(text: 'x').text_id).to be_nil
    end

    it 'raises ApiError on 401' do
      stub_api(:post, '/api/v1/texts', status: 401, body: { error: 'Missing or invalid Authorization header.' })
      expect { client.share_text(text: 'secret', ttl_hours: 1) }.to raise_error(Konfidant::ApiError) { |e|
        expect(e.status_code).to eq(401)
        expect(e.message).to eq('Missing or invalid Authorization header.')
      }
    end

    it 'raises ApiError on 400 and exposes the body' do
      stub_api(:post, '/api/v1/texts', status: 400, body: { error: 'invalid_ciphertext', message: 'Bad KNF1' })
      expect { client.share_text(text: 'secret', ttl_hours: 1) }.to raise_error(Konfidant::ApiError) { |e|
        expect(e.message).to eq('invalid_ciphertext')
        expect(e.body).to eq({ 'error' => 'invalid_ciphertext', 'message' => 'Bad KNF1' })
      }
    end

    it 'falls back to "HTTP {status}" message when body has no error field' do
      stub_request(:post, "#{base_url}/api/v1/texts").to_return(status: 500, body: 'oops')
      expect { client.share_text(text: 'secret') }.to raise_error(Konfidant::ApiError, 'HTTP 500')
    end
  end

  # ---------------------------------------------------------------------------
  # Low-level file upload steps
  # ---------------------------------------------------------------------------

  describe '#create_file_upload' do
    it 'POSTs only ciphertext_size and ttl_hours' do
      stub_request(:post, "#{base_url}/api/v1/files")
        .with(headers: { 'Authorization' => 'Bearer test-key' },
              body: { ciphertext_size: 1234, ttl_hours: 24 }.to_json)
        .to_return(status: 201, body: upload_response.to_json, headers: json_ct)

      upload = client.create_file_upload(ciphertext_size: 1234, ttl_hours: 24)
      expect(upload).to eq(Konfidant::FileUpload.new(upload_url: upload_url, file_key: 'abc123',
                                                     upload_headers: upload_headers, upload_expires_in: 900,
                                                     ciphertext_size: 1234))
    end

    it 'raises ApiError on 413' do
      stub_api(:post, '/api/v1/files', status: 413, body: { error: 'file_too_large' })
      expect { client.create_file_upload(ciphertext_size: 10**12) }
        .to raise_error(Konfidant::ApiError, 'file_too_large')
    end
  end

  describe '#upload_ciphertext' do
    let(:ciphertext) { Konfidant::Knf.encrypt(key: Konfidant::Knf.generate_key, content: 'abc', kind: 'file') }
    let(:upload) do
      Konfidant::FileUpload.new(upload_url: upload_url, file_key: 'abc123', upload_headers: upload_headers,
                                upload_expires_in: 900, ciphertext_size: ciphertext.bytesize)
    end

    it 'PUTs the bytes with exactly the upload headers and Content-Length' do
      stub_request(:put, upload_url)
        .with(body: ciphertext, headers: upload_headers.merge('Content-Length' => ciphertext.bytesize.to_s))
        .to_return(status: 200)
      expect(client.upload_ciphertext(upload: upload, ciphertext: ciphertext)).to be_nil
    end

    it 'does NOT send the Authorization header to the upload URL' do
      stub_request(:put, upload_url).to_return(status: 200)
      client.upload_ciphertext(upload: upload, ciphertext: ciphertext)
      expect(WebMock).to(have_requested(:put, upload_url).with { |req| !req.headers.key?('Authorization') })
    end

    it 'streams IO-like ciphertext' do
      stub = stub_request(:put, upload_url).with(body: ciphertext).to_return(status: 200)
      client.upload_ciphertext(upload: upload, ciphertext: StringIO.new(ciphertext))
      expect(stub).to have_been_requested
    end

    it 'defaults Content-Type to application/octet-stream when the server sends none' do
      stub = stub_request(:put, upload_url)
             .with(headers: { 'Content-Type' => 'application/octet-stream' })
             .to_return(status: 200)
      client.upload_ciphertext(upload: upload.with(upload_headers: {}), ciphertext: ciphertext)
      expect(stub).to have_been_requested
    end

    it 'refuses a ciphertext whose size differs from the declared size' do
      expect { client.upload_ciphertext(upload: upload, ciphertext: "#{ciphertext}x") }
        .to raise_error(ArgumentError, /created for/)
      expect(WebMock).not_to have_requested(:put, upload_url)
    end

    it 'raises ApiError when storage rejects the upload' do
      stub_request(:put, upload_url).to_return(status: 403, body: '<Error>SignatureDoesNotMatch</Error>')
      expect { client.upload_ciphertext(upload: upload, ciphertext: ciphertext) }
        .to raise_error(Konfidant::ApiError) { |e|
          expect(e.status_code).to eq(403)
          expect(e.message).to eq('file upload failed: HTTP 403')
        }
    end
  end

  describe '#complete_file_upload' do
    it 'POSTs with no body and returns a CompletedUpload' do
      stub_request(:post, "#{base_url}/api/v1/files/abc123/complete")
        .with(headers: { 'Authorization' => 'Bearer test-key' }) { |req| req.body.to_s.empty? }
        .to_return(status: 201, body: complete_response.to_json, headers: json_ct)

      expect(client.complete_file_upload(file_key: 'abc123'))
        .to eq(Konfidant::CompletedUpload.new(download_url: download_url, file_id: 'file-1',
                                              expires_at: '2026-10-05T00:00:00Z', verified_burn: true))
    end

    it 'percent-encodes the file_key' do
      stub_api(:post, '/api/v1/files/org%2F1%20x/complete', status: 201, body: complete_response)
      expect { client.complete_file_upload(file_key: 'org/1 x') }.not_to raise_error
    end

    it 'raises ApiError 409 upload_incomplete' do
      stub_api(:post, '/api/v1/files/abc123/complete', status: 409, body: { error: 'upload_incomplete' })
      expect { client.complete_file_upload(file_key: 'abc123') }.to raise_error(Konfidant::ApiError) { |e|
        expect(e.status_code).to eq(409)
        expect(e.message).to eq('upload_incomplete')
      }
    end
  end

  # ---------------------------------------------------------------------------
  # share_file
  # ---------------------------------------------------------------------------

  describe '#share_file' do
    let(:content) { Random.new(1).bytes(3 * 1024 * 1024) }

    it 'encrypts, uploads, completes and returns a FileShare with the key in the fragment' do
      declared = nil
      uploaded = nil
      stub_request(:post, "#{base_url}/api/v1/files")
        .with { |req| declared = JSON.parse(req.body) }
        .to_return(status: 201, body: upload_response.to_json, headers: json_ct)
      stub_request(:put, upload_url)
        .with(headers: upload_headers) { |req| uploaded = req.body.b }
        .to_return(status: 200)
      complete = stub_api(:post, '/api/v1/files/abc123/complete', status: 201, body: complete_response)

      result = client.share_file(content: StringIO.new(content), filename: 'report.pdf',
                                 content_type: 'application/pdf', ttl_hours: 24)

      expect(result).to be_a(Konfidant::FileShare)
      expect(result.share_url).to match(%r{\Ahttps://download\.konfidant\.app/#t=tok%2Ben&k=[A-Za-z0-9_-]{43}\z})
      expect(result.file_id).to eq('file-1')
      expect(result.expires_at).to eq('2026-10-05T00:00:00Z')
      expect(result.verified_burn).to be(true)
      expect(complete).to have_been_requested

      expect(declared).to eq('ciphertext_size' => uploaded.bytesize, 'ttl_hours' => 24)
      expect(uploaded).not_to include('report.pdf')
      expect(WebMock).to(have_requested(:put, upload_url).with do |req|
        req.headers['Content-Length'] == uploaded.bytesize.to_s && !req.headers.key?('Authorization')
      end)

      decrypted = Konfidant::Knf.decrypt(key: key_from(result.share_url), ciphertext: uploaded)
      expect(decrypted.kind).to eq('file')
      expect(decrypted.name).to eq('report.pdf')
      expect(decrypted.mime).to eq('application/pdf')
      expect(decrypted.data).to eq(content)
    end

    it 'accepts a String and an empty content type' do
      uploaded = nil
      stub_api(:post, '/api/v1/files', status: 201, body: upload_response)
      stub_request(:put, upload_url).with { |req| uploaded = req.body.b }.to_return(status: 200)
      stub_api(:post, '/api/v1/files/abc123/complete', status: 201, body: complete_response)

      result = client.share_file(content: 'hello', filename: 'a.txt')
      decrypted = Konfidant::Knf.decrypt(key: key_from(result.share_url), ciphertext: uploaded)
      expect([decrypted.data, decrypted.mime]).to eq(['hello', ''])
    end

    it 'uses a different key for every share' do
      stub_api(:post, '/api/v1/files', status: 201, body: upload_response)
      stub_request(:put, upload_url).to_return(status: 200)
      stub_api(:post, '/api/v1/files/abc123/complete', status: 201, body: complete_response)

      urls = Array.new(2) { client.share_file(content: 'x', filename: 'a').share_url }
      expect(urls.uniq.size).to eq(2)
    end

    it 'rejects a file name over 1024 bytes before any request' do
      expect { client.share_file(content: 'x', filename: 'a' * 1025) }.to raise_error(Konfidant::KnfError)
      expect(WebMock).not_to have_requested(:any, /.*/)
    end

    it 'propagates 409 from complete' do
      stub_api(:post, '/api/v1/files', status: 201, body: upload_response)
      stub_request(:put, upload_url).to_return(status: 200)
      stub_api(:post, '/api/v1/files/abc123/complete', status: 409, body: { error: 'upload_incomplete' })
      expect { client.share_file(content: 'x', filename: 'a') }
        .to raise_error(Konfidant::ApiError, 'upload_incomplete')
    end

    it 'does not complete when the upload fails' do
      stub_api(:post, '/api/v1/files', status: 201, body: upload_response)
      stub_request(:put, upload_url).to_return(status: 500)
      complete = stub_api(:post, '/api/v1/files/abc123/complete', status: 201, body: complete_response)
      expect { client.share_file(content: 'x', filename: 'a') }.to raise_error(Konfidant::ApiError)
      expect(complete).not_to have_been_requested
    end
  end

  # ---------------------------------------------------------------------------
  # open_share
  # ---------------------------------------------------------------------------

  describe '#open_share' do
    let(:key) { Konfidant::Knf.generate_key }
    let(:share_url) { Konfidant::Knf.build_share_url('https://share.example.com/#t=tok%2Ben', key) }

    def stub_download(ciphertext)
      stub_request(:post, 'https://share.example.com/api/download')
        .with(body: { t: 'tok+en' }.to_json, headers: { 'Content-Type' => 'application/json' })
        .to_return(status: 200, body: ciphertext, headers: { 'Content-Type' => 'application/octet-stream' })
    end

    it 'fetches with the token only and decrypts a text share' do
      stub_download(Konfidant::Knf.encrypt_text(key: key, text: "hello \u{1F510}"))
      result = client.open_share(share_url)

      expect(result.kind).to eq('text')
      expect(result.text).to eq("hello \u{1F510}")
      expect(result.data).to eq("hello \u{1F510}".b)
      expect([result.name, result.mime]).to eq(['', ''])
      expect(WebMock).to(have_requested(:post, 'https://share.example.com/api/download').with do |req|
        !req.headers.key?('Authorization') && !req.body.include?(Konfidant::Knf.encode_key(key))
      end)
    end

    it 'decrypts a multi-chunk file share' do
      content = Random.new(3).bytes((2 * 1024 * 1024) + 17)
      stub_download(Konfidant::Knf.encrypt(key: key, content: content, kind: 'file', name: 'ü.bin', mime: 'x/y'))
      result = client.open_share(share_url)

      expect(result.kind).to eq('file')
      expect(result.name).to eq('ü.bin')
      expect(result.mime).to eq('x/y')
      expect(result.data).to eq(content)
      expect(result.text).to be_nil
    end

    it 'raises ApiError 410 when already used or expired' do
      stub_request(:post, 'https://share.example.com/api/download')
        .to_return(status: 410, body: { error: 'gone' }.to_json, headers: json_ct)
      expect { client.open_share(share_url) }.to raise_error(Konfidant::ApiError) { |e|
        expect(e.status_code).to eq(410)
      }
    end

    it 'raises KnfError for the wrong key' do
      stub_download(Konfidant::Knf.encrypt_text(key: Konfidant::Knf.generate_key, text: 'x'))
      expect { client.open_share(share_url) }.to raise_error(Konfidant::KnfError)
    end

    it 'raises ArgumentError for a link without a key' do
      expect { client.open_share('https://share.example.com/#t=tok') }.to raise_error(ArgumentError)
    end
  end

  # ---------------------------------------------------------------------------
  # list_shares
  # ---------------------------------------------------------------------------

  describe '#list_shares' do
    let(:list_response) do
      {
        'shares' => [
          { 'type' => 'file', 'file_size_bytes' => 2048, 'created_at' => '2026-10-01T00:00:00Z',
            'expires_at' => '2026-10-03T00:00:00Z', 'accessed_at' => nil, 'created_by' => 'a@example.com' },
          { 'type' => 'text', 'created_at' => '2026-10-01T00:00:00Z', 'expires_at' => '2026-10-03T00:00:00Z',
            'accessed_at' => '2026-10-02T00:00:00Z', 'created_by' => nil }
        ],
        'pagination' => { 'total' => 2, 'limit' => 50, 'offset' => 0, 'has_more' => false }
      }
    end

    it 'GET /api/v1/shares with auth and no params' do
      stub = stub_request(:get, "#{base_url}/api/v1/shares")
             .with(headers: { 'Authorization' => 'Bearer test-key' })
             .to_return(status: 200, body: empty_list.to_json, headers: json_ct)
      client.list_shares
      expect(stub).to have_been_requested
    end

    it 'appends only the given query params' do
      stub = stub_api(:get, '/api/v1/shares?type=file&limit=10', status: 200, body: empty_list)
      client.list_shares(type: 'file', limit: 10)
      expect(stub).to have_been_requested

      stub = stub_api(:get, '/api/v1/shares?type=text&status=active&limit=5&offset=10', status: 200,
                                                                                         body: empty_list)
      client.list_shares(type: 'text', status: 'active', limit: 5, offset: 10)
      expect(stub).to have_been_requested
    end

    it 'returns shares (without file names) and pagination' do
      stub_api(:get, '/api/v1/shares', status: 200, body: list_response)
      result = client.list_shares

      expect(result.shares.size).to eq(2)
      expect(result.shares.first).to eq(
        Konfidant::Share.new(type: 'file', file_size_bytes: 2048, created_at: '2026-10-01T00:00:00Z',
                             expires_at: '2026-10-03T00:00:00Z', accessed_at: nil, created_by: 'a@example.com')
      )
      expect(result.shares.first).not_to respond_to(:file_name)
      expect(result.shares.last.accessed_at).to eq('2026-10-02T00:00:00Z')
      expect(result.pagination).to eq(Konfidant::Pagination.new(total: 2, limit: 50, offset: 0, has_more: false))
    end

    it 'raises ApiError on 403' do
      stub_api(:get, '/api/v1/shares', status: 403, body: { error: 'Insufficient scope' })
      expect { client.list_shares }.to raise_error(Konfidant::ApiError, 'Insufficient scope')
    end
  end

  describe 'removed API' do
    it 'no longer exposes the plaintext/polling methods' do
      %i[share_and_upload_file get_file_status upload_file].each do |m|
        expect(client).not_to respond_to(m)
      end
    end
  end
end

RSpec.describe Konfidant::ApiError do
  it 'carries status_code, body, and message' do
    err = described_class.new('Unauthorized', 401, { 'error' => 'Unauthorized' })
    expect(err.message).to eq('Unauthorized')
    expect(err.status_code).to eq(401)
    expect(err.body).to eq({ 'error' => 'Unauthorized' })
  end

  it 'shares a base class with KnfError' do
    expect(described_class.ancestors).to include(Konfidant::Error)
    expect(Konfidant::KnfError.ancestors).to include(Konfidant::Error)
  end
end
