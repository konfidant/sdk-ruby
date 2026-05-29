RSpec.describe Konfidant::Client do
  let(:base_url)   { 'http://api.test' }
  let(:client)     { described_class.new(api_key: 'test-key', base_url: base_url) }
  let(:json_ct)    { { 'Content-Type' => 'application/json' } }

  def stub_api(method, path, status:, body:)
    stub_request(method, "#{base_url}#{path}")
      .to_return(status: status, body: body.to_json, headers: json_ct)
  end

  def presigned_response(upload_url: 'http://s3.test/upload')
    {
      'upload_url' => upload_url,
      'file_key'   => 'abc123.zip',
      'poll_url'   => "#{base_url}/api/v1/files/abc123.zip/status",
      'metadata_headers' => {
        'x-amz-meta-user-id'         => 'user-1',
        'x-amz-meta-ttl-hours'       => '48',
        'x-amz-meta-organization-id' => 'org-1'
      }
    }
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
      stub_request(:get, 'https://example.com/api/v1/shares').to_return(
        status: 200,
        body:   { 'shares' => [], 'pagination' => { 'total' => 0, 'limit' => 50, 'offset' => 0, 'has_more' => false } }.to_json,
        headers: json_ct
      )
      expect { c.list_shares }.not_to raise_error
    end

    it 'defaults to production base URL' do
      c = described_class.new(api_key: 'k')
      stub_request(:get, 'https://www.konfidant.app/api/v1/shares').to_return(
        status: 200,
        body:   { 'shares' => [], 'pagination' => { 'total' => 0, 'limit' => 50, 'offset' => 0, 'has_more' => false } }.to_json,
        headers: json_ct
      )
      expect { c.list_shares }.not_to raise_error
    end

    it 'accepts nil http_timeout to disable timeout' do
      expect { described_class.new(api_key: 'k', http_timeout: nil) }.not_to raise_error
    end
  end

  # ---------------------------------------------------------------------------
  # share_text
  # ---------------------------------------------------------------------------

  describe '#share_text' do
    let(:expected_response) do
      {
        'text_id'      => 'abc',
        'share_url'    => 'https://download.konfidant.app?t=tok',
        'expires_at'   => '2026-06-01 00:00:00',
        'verified_burn' => true
      }
    end

    it 'POST /api/v1/texts with correct body and auth header' do
      stub = stub_request(:post, "#{base_url}/api/v1/texts")
        .with(
          body:    { text: 'Secret', ttl_hours: 24 }.to_json,
          headers: { 'Authorization' => 'Bearer test-key', 'Content-Type' => 'application/json' }
        )
        .to_return(status: 201, body: expected_response.to_json, headers: json_ct)

      result = client.share_text(text: 'Secret', ttl_hours: 24)

      expect(stub).to have_been_requested
      expect(result.text_id).to eq('abc')
      expect(result.share_url).to eq('https://download.konfidant.app?t=tok')
      expect(result.verified_burn).to be(true)
    end

    it 'returns a ShareTextResponse' do
      stub_api(:post, '/api/v1/texts', status: 201, body: expected_response)
      result = client.share_text(text: 'x', ttl_hours: 1)
      expect(result).to be_a(Konfidant::ShareTextResponse)
    end

    it 'raises ApiError on 401' do
      stub_api(:post, '/api/v1/texts', status: 401, body: { 'error' => 'Missing or invalid Authorization header.' })
      expect { client.share_text(text: 'x', ttl_hours: 1) }
        .to raise_error(Konfidant::ApiError) { |e|
          expect(e.status_code).to eq(401)
          expect(e.message).to eq('Missing or invalid Authorization header.')
        }
    end

    it 'raises ApiError on 400' do
      stub_api(:post, '/api/v1/texts', status: 400, body: { 'error' => 'Invalid JSON body' })
      expect { client.share_text(text: '', ttl_hours: 0) }.to raise_error(Konfidant::ApiError)
    end

    it 'falls back to "HTTP {status}" message when body has no error field' do
      stub_request(:post, "#{base_url}/api/v1/texts")
        .to_return(status: 500, body: 'Internal Server Error', headers: { 'Content-Type' => 'text/plain' })
      expect { client.share_text(text: 'x', ttl_hours: 1) }
        .to raise_error(Konfidant::ApiError) { |e|
          expect(e.status_code).to eq(500)
          expect(e.message).to eq('HTTP 500')
        }
    end
  end

  # ---------------------------------------------------------------------------
  # share_file
  # ---------------------------------------------------------------------------

  describe '#share_file' do
    it 'POST /api/v1/files and returns ShareFileResponse' do
      stub = stub_request(:post, "#{base_url}/api/v1/files")
        .with(body: { filename: 'doc.pdf', file_size: 1024, ttl_hours: 48 }.to_json)
        .to_return(status: 202, body: presigned_response.to_json, headers: json_ct)

      result = client.share_file(filename: 'doc.pdf', file_size: 1024, ttl_hours: 48)

      expect(stub).to have_been_requested
      expect(result).to be_a(Konfidant::ShareFileResponse)
      expect(result.file_key).to eq('abc123.zip')
      expect(result.metadata_headers.user_id).to eq('user-1')
      expect(result.metadata_headers.ttl_hours).to eq('48')
      expect(result.metadata_headers.organization_id).to eq('org-1')
    end

    it 'raises ApiError on 401' do
      stub_api(:post, '/api/v1/files', status: 401, body: { 'error' => 'Unauthorized' })
      expect { client.share_file(filename: 'x', file_size: 1, ttl_hours: 1) }
        .to raise_error(Konfidant::ApiError) { |e| expect(e.status_code).to eq(401) }
    end

    it 'includes upload_url and poll_url in response' do
      stub_request(:post, "#{base_url}/api/v1/files")
        .to_return(status: 202, body: presigned_response.to_json, headers: json_ct)

      result = client.share_file(filename: 'doc.pdf', file_size: 1024, ttl_hours: 48)

      expect(result.upload_url).to eq('http://s3.test/upload')
      expect(result.poll_url).to eq("#{base_url}/api/v1/files/abc123.zip/status")
    end
  end

  # ---------------------------------------------------------------------------
  # get_file_status
  # ---------------------------------------------------------------------------

  describe '#get_file_status' do
    it 'returns FileStatusResponse with processing status' do
      stub_api(:get, '/api/v1/files/abc123.zip/status', status: 202,
               body: { 'status' => 'processing', 'message' => 'Encryption in progress' })

      result = client.get_file_status('abc123.zip')

      expect(result).to be_a(Konfidant::FileStatusResponse)
      expect(result.status).to eq('processing')
      expect(result.message).to eq('Encryption in progress')
    end

    it 'returns FileStatusResponse with complete status' do
      complete = {
        'status'        => 'complete',
        'file_id'       => 'file-1',
        'file_name'     => 'doc.pdf',
        'share_url'     => 'https://download.konfidant.app?t=tok',
        'expires_at'    => '2026-06-01 00:00:00',
        'verified_burn' => true
      }
      stub_api(:get, '/api/v1/files/abc123.zip/status', status: 200, body: complete)

      result = client.get_file_status('abc123.zip')

      expect(result.status).to eq('complete')
      expect(result.file_id).to eq('file-1')
      expect(result.verified_burn).to be(true)
    end

    it 'percent-encodes file_key in path' do
      stub = stub_request(:get, "#{base_url}/api/v1/files/has%20spaces.zip/status")
        .to_return(
          status:  200,
          body:    { 'status' => 'complete', 'file_id' => 'x', 'file_name' => 'x',
                     'share_url' => 'x', 'expires_at' => 'x' }.to_json,
          headers: json_ct
        )

      client.get_file_status('has spaces.zip')

      expect(stub).to have_been_requested
    end

    it 'raises ApiError on 404' do
      stub_api(:get, '/api/v1/files/nope/status', status: 404, body: { 'error' => 'File not found' })
      expect { client.get_file_status('nope') }
        .to raise_error(Konfidant::ApiError) { |e| expect(e.status_code).to eq(404) }
    end

    it 'processing status has nil share fields' do
      stub_api(:get, '/api/v1/files/abc123.zip/status', status: 202,
               body: { 'status' => 'processing', 'message' => 'Encryption in progress' })

      result = client.get_file_status('abc123.zip')

      expect(result.file_id).to be_nil
      expect(result.file_name).to be_nil
      expect(result.share_url).to be_nil
      expect(result.expires_at).to be_nil
    end
  end

  # ---------------------------------------------------------------------------
  # list_shares
  # ---------------------------------------------------------------------------

  describe '#list_shares' do
    let(:empty_response) do
      { 'shares' => [], 'pagination' => { 'total' => 0, 'limit' => 50, 'offset' => 0, 'has_more' => false } }
    end

    it 'GET /api/v1/shares with no params' do
      stub = stub_request(:get, "#{base_url}/api/v1/shares")
        .to_return(status: 200, body: empty_response.to_json, headers: json_ct)

      client.list_shares

      expect(stub).to have_been_requested
    end

    it 'appends all query params' do
      stub = stub_request(:get, "#{base_url}/api/v1/shares")
        .with(query: { 'type' => 'file', 'status' => 'active', 'limit' => '10', 'offset' => '20' })
        .to_return(status: 200, body: empty_response.to_json, headers: json_ct)

      client.list_shares(type: 'file', status: 'active', limit: 10, offset: 20)

      expect(stub).to have_been_requested
    end

    it 'returns shares and pagination' do
      body = {
        'shares' => [
          {
            'type'            => 'file',
            'file_name'       => 'doc.pdf',
            'file_size_bytes' => 1024,
            'created_at'      => '2026-05-01T00:00:00.000Z',
            'expires_at'      => '2026-05-08T00:00:00.000Z',
            'accessed_at'     => nil,
            'created_by'      => 'user@example.com'
          }
        ],
        'pagination' => { 'total' => 1, 'limit' => 50, 'offset' => 0, 'has_more' => false }
      }
      stub_api(:get, '/api/v1/shares', status: 200, body: body)

      result = client.list_shares

      expect(result).to be_a(Konfidant::ListSharesResponse)
      expect(result.shares.length).to eq(1)
      expect(result.shares.first.file_name).to eq('doc.pdf')
      expect(result.shares.first.accessed_at).to be_nil
      expect(result.pagination.total).to eq(1)
      expect(result.pagination.has_more).to be(false)
    end

    it 'omits absent params from query string' do
      stub = stub_request(:get, "#{base_url}/api/v1/shares")
        .with(query: { 'type' => 'text' })
        .to_return(status: 200, body: empty_response.to_json, headers: json_ct)

      client.list_shares(type: 'text')

      expect(stub).to have_been_requested
    end

    it 'supports has_more pagination' do
      body = {
        'shares'     => [],
        'pagination' => { 'total' => 100, 'limit' => 10, 'offset' => 0, 'has_more' => true }
      }
      stub_request(:get, "#{base_url}/api/v1/shares")
        .with(query: { 'limit' => '10' })
        .to_return(status: 200, body: body.to_json, headers: json_ct)

      result = client.list_shares(limit: 10)

      expect(result.pagination.has_more).to be(true)
      expect(result.pagination.total).to eq(100)
    end

    it 'raises ApiError on 403 with scope info' do
      stub_api(:get, '/api/v1/shares', status: 403, body: {
        'error'            => 'Insufficient permissions',
        'required_scope'   => 'shares:list',
        'available_scopes' => ['files:create']
      })
      expect { client.list_shares }
        .to raise_error(Konfidant::ApiError) { |e|
          expect(e.status_code).to eq(403)
          expect(e.message).to eq('Insufficient permissions')
        }
    end
  end

  # ---------------------------------------------------------------------------
  # upload_file
  # ---------------------------------------------------------------------------

  describe '#upload_file' do
    let(:s3_url)   { 'http://s3.test/upload' }
    let(:presigned) do
      Konfidant::ShareFileResponse.new(
        upload_url:       s3_url,
        file_key:         'abc123.zip',
        poll_url:         "#{base_url}/api/v1/files/abc123.zip/status",
        metadata_headers: Konfidant::FileMetadataHeaders.new(
          user_id:         'user-1',
          ttl_hours:       '48',
          organization_id: 'org-1'
        )
      )
    end

    it 'PUT to upload_url with correct S3 metadata headers' do
      stub = stub_request(:put, s3_url)
        .with(
          body:    'hello',
          headers: {
            'Content-Type'               => 'text/plain',
            'X-Amz-Meta-Organization-Id' => 'org-1',
            'X-Amz-Meta-Ttl-Hours'       => '48',
            'X-Amz-Meta-User-Id'         => 'user-1'
          }
        )
        .to_return(status: 200)

      client.upload_file(io: StringIO.new('hello'), size: 5, content_type: 'text/plain', presigned: presigned)

      expect(stub).to have_been_requested
    end

    it 'does NOT send Konfidant Authorization header to S3' do
      captured_auth = nil
      stub_request(:put, s3_url).to_return do |request|
        captured_auth = request.headers['Authorization']
        { status: 200 }
      end

      client.upload_file(io: StringIO.new('x'), size: 1, content_type: 'text/plain', presigned: presigned)

      expect(captured_auth).to be_nil
    end

    it 'raises ApiError when S3 returns an error' do
      stub_request(:put, s3_url).to_return(status: 403, body: 'AccessDenied')

      expect {
        client.upload_file(io: StringIO.new('x'), size: 1, content_type: 'text/plain', presigned: presigned)
      }.to raise_error(Konfidant::ApiError) { |e|
        expect(e.status_code).to eq(403)
        expect(e.message).to include('file upload failed')
      }
    end
  end

  # ---------------------------------------------------------------------------
  # share_and_upload_file
  # ---------------------------------------------------------------------------

  describe '#share_and_upload_file' do
    let(:s3_url)  { 'http://s3.test/upload' }
    let(:presigned) { presigned_response(upload_url: s3_url) }
    let(:processing) { { 'status' => 'processing', 'message' => 'Encryption in progress' } }
    let(:complete) do
      {
        'status'        => 'complete',
        'file_id'       => 'file-1',
        'file_name'     => 'doc.pdf',
        'share_url'     => 'https://download.konfidant.app?t=tok',
        'expires_at'    => '2026-06-01 00:00:00',
        'verified_burn' => true
      }
    end

    it 'calls share_file → upload_file → polls until complete' do
      stub_api(:post, '/api/v1/files', status: 202, body: presigned)
      stub_request(:put, s3_url).to_return(status: 200)
      stub_request(:get, "#{base_url}/api/v1/files/abc123.zip/status")
        .to_return(
          { status: 202, body: processing.to_json, headers: json_ct },
          { status: 200, body: complete.to_json,    headers: json_ct }
        )

      result = client.share_and_upload_file(
        io:           StringIO.new('data'),
        size:         4,
        filename:     'doc.pdf',
        content_type: 'application/pdf',
        ttl_hours:    48,
        poll_interval: 0.01,
        timeout:      5
      )

      expect(result).to be_a(Konfidant::ShareResult)
      expect(result.share_url).to eq('https://download.konfidant.app?t=tok')
      expect(result.file_id).to eq('file-1')
      expect(result.verified_burn).to be(true)
    end

    it 'raises when encryption times out' do
      stub_api(:post, '/api/v1/files', status: 202, body: presigned)
      stub_request(:put, s3_url).to_return(status: 200)
      stub_request(:get, "#{base_url}/api/v1/files/abc123.zip/status")
        .to_return(status: 202, body: processing.to_json, headers: json_ct)

      expect {
        client.share_and_upload_file(
          io:           StringIO.new('data'),
          size:         4,
          filename:     'doc.pdf',
          content_type: 'application/pdf',
          ttl_hours:    48,
          poll_interval: 0.01,
          timeout:      0.05
        )
      }.to raise_error(/timed out/)
    end

    it 'propagates ApiError from share_file' do
      stub_api(:post, '/api/v1/files', status: 401, body: { 'error' => 'Unauthorized' })

      expect {
        client.share_and_upload_file(
          io: StringIO.new('data'), size: 4, filename: 'doc.pdf',
          content_type: 'application/pdf', ttl_hours: 48
        )
      }.to raise_error(Konfidant::ApiError) { |e| expect(e.status_code).to eq(401) }
    end

    it 'propagates ApiError from upload_file' do
      stub_api(:post, '/api/v1/files', status: 202, body: presigned)
      stub_request(:put, s3_url).to_return(status: 403, body: 'AccessDenied')

      expect {
        client.share_and_upload_file(
          io: StringIO.new('data'), size: 4, filename: 'doc.pdf',
          content_type: 'application/pdf', ttl_hours: 48
        )
      }.to raise_error(Konfidant::ApiError) { |e| expect(e.status_code).to eq(403) }
    end

    it 'propagates ApiError from get_file_status' do
      stub_api(:post, '/api/v1/files', status: 202, body: presigned)
      stub_request(:put, s3_url).to_return(status: 200)
      stub_api(:get, '/api/v1/files/abc123.zip/status', status: 500,
               body: { 'error' => 'Internal Server Error' })

      expect {
        client.share_and_upload_file(
          io: StringIO.new('data'), size: 4, filename: 'doc.pdf',
          content_type: 'application/pdf', ttl_hours: 48, timeout: 5
        )
      }.to raise_error(Konfidant::ApiError) { |e| expect(e.status_code).to eq(500) }
    end
  end

end

# ---------------------------------------------------------------------------
# ApiError
# ---------------------------------------------------------------------------

RSpec.describe Konfidant::ApiError do
  let(:base_url) { 'http://api.test' }
  let(:client)   { Konfidant::Client.new(api_key: 'test-key', base_url: base_url) }
  let(:json_ct)  { { 'Content-Type' => 'application/json' } }

  it 'carries status_code, body, and message' do
    err = described_class.new('Unauthorized', 401, { 'error' => 'Unauthorized' })
    expect(err.status_code).to eq(401)
    expect(err.body).to eq({ 'error' => 'Unauthorized' })
    expect(err.message).to eq('Unauthorized')
    expect(err).to be_a(StandardError)
  end

  it 'uses error field from JSON body as message' do
    stub_request(:post, "#{base_url}/api/v1/texts")
      .to_return(status: 401,
                 body:   { 'error' => 'Missing or invalid Authorization header.' }.to_json,
                 headers: json_ct)
    begin
      client.share_text(text: 'x', ttl_hours: 1)
    rescue Konfidant::ApiError => e
      expect(e.message).to eq('Missing or invalid Authorization header.')
      expect(e.status_code).to eq(401)
      expect(e.body).to be_a(Hash)
    end
  end
end
