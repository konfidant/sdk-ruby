require 'net/http'
require 'uri'
require 'json'

module Konfidant
  DEFAULT_BASE_URL = 'https://www.konfidant.app'
  DEFAULT_TIMEOUT  = 120

  # Konfidant API client. All content is encrypted locally (KNF1) before it leaves this process; the key is only
  # ever placed in the returned share link's URL fragment and is never sent to Konfidant.
  class Client
    def initialize(api_key:, base_url: nil, http_timeout: DEFAULT_TIMEOUT)
      raise ArgumentError, 'api_key is required' if api_key.nil? || api_key.empty?

      @api_key      = api_key
      @base_url     = (base_url || DEFAULT_BASE_URL).sub(%r{/+\z}, '')
      @http_timeout = http_timeout
    end

    # Encrypts +text+ locally and shares it. Returns a TextShare whose +share_url+ contains the key.
    def share_text(text:, ttl_hours: nil)
      key        = Knf.generate_key
      ciphertext = Knf.encrypt_text(key: key, text: text)
      payload    = with_ttl({ ciphertext: [ciphertext].pack('m0') }, ttl_hours)
      body       = api_request(:post, '/api/v1/texts', payload)

      TextShare.new(
        share_url:  Knf.build_share_url(body['download_url'], key),
        text_id:    body['text_id'],
        expires_at: body['expires_at']
      )
    end

    # Encrypts a file locally, uploads the ciphertext and completes the share. Returns a FileShare whose
    # +share_url+ contains the key.
    #
    # +content+ is a String of file bytes or a readable IO (File, StringIO, ...). IOs with a known size are
    # streamed chunk by chunk. +filename+ and +content_type+ are encrypted together with the content.
    def share_file(content:, filename:, content_type: '', ttl_hours: nil)
      key       = Knf.generate_key
      encryptor = Knf.encryptor(key: key, content: content, kind: 'file', name: filename, mime: content_type)
      upload    = create_file_upload(ciphertext_size: encryptor.size, ttl_hours: ttl_hours)
      upload_ciphertext(upload: upload, ciphertext: encryptor)
      completed = complete_file_upload(file_key: upload.file_key)

      FileShare.new(
        share_url:     Knf.build_share_url(completed.download_url, key),
        file_id:       completed.file_id,
        expires_at:    completed.expires_at,
        verified_burn: completed.verified_burn
      )
    end

    # Low level, step 1: reserves an upload for exactly +ciphertext_size+ KNF1 bytes.
    def create_file_upload(ciphertext_size:, ttl_hours: nil)
      payload = with_ttl({ ciphertext_size: ciphertext_size }, ttl_hours)
      body    = api_request(:post, '/api/v1/files', payload)

      FileUpload.new(
        upload_url:        body['upload_url'],
        file_key:          body['file_key'],
        upload_headers:    body['upload_headers'] || {},
        upload_expires_in: body['upload_expires_in'],
        ciphertext_size:   ciphertext_size
      )
    end

    # Low level, step 2: PUTs the KNF1 ciphertext (a binary String, or an IO-like object such as a Knf::Encryptor)
    # to the upload URL with exactly the server-provided headers. The API key is never sent to the upload URL.
    def upload_ciphertext(upload:, ciphertext:)
      size   = upload.ciphertext_size
      actual = byte_size(ciphertext)
      if actual && actual != size
        raise ArgumentError, "ciphertext is #{actual} bytes but the upload was created for #{size} bytes"
      end

      uri = URI.parse(upload.upload_url)
      req = Net::HTTP::Put.new(uri)
      upload.upload_headers.each { |name, value| req[name] = value.to_s }
      # Only when the server did not specify one: Net::HTTP would otherwise send application/x-www-form-urlencoded.
      req['Content-Type'] ||= 'application/octet-stream'
      req['Content-Length'] = size.to_s
      if ciphertext.is_a?(String)
        req.body = ciphertext.b
      else
        req.body_stream = ciphertext
      end

      resp = perform(uri, req)
      return nil if success?(resp)

      raise ApiError.new("file upload failed: HTTP #{resp.code}", resp.code.to_i, resp.body)
    end

    # Low level, step 3: finalizes the upload. Raises ApiError (409, "upload_incomplete") if the PUT did not land.
    def complete_file_upload(file_key:)
      body = api_request(:post, "/api/v1/files/#{encode_path_segment(file_key)}/complete")

      CompletedUpload.new(
        download_url:  body['download_url'],
        file_id:       body['file_id'],
        expires_at:    body['expires_at'],
        verified_burn: body['verified_burn']
      )
    end

    def list_shares(type: nil, status: nil, limit: nil, offset: nil)
      params = { type: type, status: status, limit: limit, offset: offset }.compact

      path = '/api/v1/shares'
      path += "?#{URI.encode_www_form(params)}" unless params.empty?

      body = api_request(:get, path)
      ListSharesResponse.new(
        shares:     body['shares'].map { |s| parse_share(s) },
        pagination: parse_pagination(body['pagination'])
      )
    end

    # Recipient side: fetches the ciphertext behind +share_url+ (consuming its single-use token) and decrypts it
    # locally. Only the token is sent; the key and the API key are not. Raises ApiError (410) if the share was
    # already opened or has expired, KnfError if decryption fails.
    def open_share(share_url)
      origin, token, key = Knf.parse_share_url(share_url)
      uri = URI.parse("#{origin}/api/download")
      req = Net::HTTP::Post.new(uri)
      req['Content-Type'] = 'application/json'
      req['Accept']       = 'application/octet-stream'
      req.body = JSON.generate({ t: token })

      ciphertext = handle_response(perform(uri, req))
      raise KnfError, 'Unexpected download response' unless ciphertext.is_a?(String)

      decrypted = Knf.decrypt(key: key, ciphertext: ciphertext.b)
      OpenedShare.new(
        kind: decrypted.kind,
        name: decrypted.name,
        mime: decrypted.mime,
        data: decrypted.data,
        text: decrypted.kind == 'text' ? decrypted.text : nil
      )
    end

    private

    def with_ttl(payload, ttl_hours)
      ttl_hours.nil? ? payload : payload.merge(ttl_hours: ttl_hours)
    end

    def byte_size(ciphertext)
      return ciphertext.bytesize if ciphertext.is_a?(String)

      ciphertext.size if ciphertext.respond_to?(:size)
    end

    def build_http(uri)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      unless @http_timeout.nil?
        http.open_timeout  = @http_timeout
        http.read_timeout  = @http_timeout
        http.write_timeout = @http_timeout
      end
      http
    end

    def perform(uri, req)
      build_http(uri).request(req)
    end

    def success?(resp)
      resp.code.to_i.between?(200, 299)
    end

    def api_request(method, path, payload = nil)
      uri = URI.parse("#{@base_url}#{path}")
      req = method == :get ? Net::HTTP::Get.new(uri) : Net::HTTP::Post.new(uri)
      req['Authorization'] = "Bearer #{@api_key}"
      if payload
        req['Content-Type'] = 'application/json'
        req.body = JSON.generate(payload)
      elsif method == :post
        req.body = ''
      end

      handle_response(perform(uri, req))
    end

    def handle_response(resp)
      content_type = resp['content-type'] || ''
      body = content_type.include?('application/json') ? parse_json(resp.body) : resp.body

      return body if success?(resp)

      message = body.is_a?(Hash) && body['error'] ? body['error'] : "HTTP #{resp.code}"
      raise ApiError.new(message, resp.code.to_i, body)
    end

    def parse_json(raw)
      JSON.parse(raw.to_s)
    rescue JSON::ParserError
      raw
    end

    def encode_path_segment(str)
      str.to_s.gsub(/[^A-Za-z0-9\-._~]/) { |c| c.bytes.map { |b| format('%%%02X', b) }.join }
    end

    def parse_share(s)
      Share.new(
        type:            s['type'],
        file_size_bytes: s['file_size_bytes'],
        created_at:      s['created_at'],
        expires_at:      s['expires_at'],
        accessed_at:     s['accessed_at'],
        created_by:      s['created_by']
      )
    end

    def parse_pagination(p)
      Pagination.new(
        total:    p['total'],
        limit:    p['limit'],
        offset:   p['offset'],
        has_more: p['has_more']
      )
    end
  end
end
