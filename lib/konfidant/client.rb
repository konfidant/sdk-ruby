require 'net/http'
require 'uri'
require 'json'

module Konfidant
  DEFAULT_BASE_URL = 'https://www.konfidant.app'
  DEFAULT_TIMEOUT  = 120

  class Client
    def initialize(api_key:, base_url: nil, http_timeout: DEFAULT_TIMEOUT)
      raise ArgumentError, 'api_key is required' if api_key.nil? || api_key.empty?

      @api_key      = api_key
      @base_url     = (base_url || DEFAULT_BASE_URL).sub(%r{/+\z}, '')
      @http_timeout = http_timeout
    end

    def share_text(text:, ttl_hours:)
      body = request(:post, '/api/v1/texts', { text: text, ttl_hours: ttl_hours })
      ShareTextResponse.new(
        text_id:      body['text_id'],
        share_url:    body['share_url'],
        expires_at:   body['expires_at'],
        verified_burn: body['verified_burn']
      )
    end

    def share_file(filename:, file_size:, ttl_hours:)
      body = request(:post, '/api/v1/files', { filename: filename, file_size: file_size, ttl_hours: ttl_hours })
      h = body['metadata_headers']
      ShareFileResponse.new(
        upload_url:       body['upload_url'],
        file_key:         body['file_key'],
        metadata_headers: FileMetadataHeaders.new(
          user_id:         h['x-amz-meta-user-id'],
          ttl_hours:       h['x-amz-meta-ttl-hours'],
          organization_id: h['x-amz-meta-organization-id']
        ),
        poll_url: body['poll_url']
      )
    end

    def get_file_status(file_key)
      encoded = encode_path_segment(file_key)
      body = request(:get, "/api/v1/files/#{encoded}/status")
      FileStatusResponse.new(
        status:        body['status'],
        message:       body['message'],
        file_id:       body['file_id'],
        file_name:     body['file_name'],
        share_url:     body['share_url'],
        expires_at:    body['expires_at'],
        verified_burn: body['verified_burn']
      )
    end

    def list_shares(type: nil, status: nil, limit: nil, offset: nil)
      params = {}
      params[:type]   = type   if type
      params[:status] = status if status
      params[:limit]  = limit  if limit
      params[:offset] = offset if offset

      path = '/api/v1/shares'
      path += "?#{URI.encode_www_form(params)}" unless params.empty?

      body = request(:get, path)
      ListSharesResponse.new(
        shares:     body['shares'].map { |s| parse_share(s) },
        pagination: parse_pagination(body['pagination'])
      )
    end

    def upload_file(io:, size:, content_type:, presigned:)
      uri  = URI.parse(presigned.upload_url)
      http = build_http(uri)

      req = Net::HTTP::Put.new(uri.request_uri)
      req['Content-Type']               = content_type
      req['Content-Length']             = size.to_s
      req['x-amz-meta-organization-id'] = presigned.metadata_headers.organization_id
      req['x-amz-meta-ttl-hours']       = presigned.metadata_headers.ttl_hours
      req['x-amz-meta-user-id']         = presigned.metadata_headers.user_id
      req.body_stream = io

      resp = http.request(req)
      return if resp.code.to_i.between?(200, 299)

      raise ApiError.new("file upload failed: HTTP #{resp.code}", resp.code.to_i, resp.body)
    end

    def share_and_upload_file(io:, size:, filename:, content_type:, ttl_hours:,
                              poll_interval: 2, timeout: 60)
      presigned = share_file(filename: filename, file_size: size, ttl_hours: ttl_hours)
      upload_file(io: io, size: size, content_type: content_type, presigned: presigned)

      deadline = Time.now + timeout
      while Time.now < deadline
        status = get_file_status(presigned.file_key)
        if status.status == 'complete'
          return ShareResult.new(
            share_url:    status.share_url,
            file_id:      status.file_id,
            expires_at:   status.expires_at,
            verified_burn: status.verified_burn
          )
        end
        sleep(poll_interval)
      end

      raise "konfidant: encryption timed out after #{timeout}s"
    end

    private

    def auth_headers
      {
        'Authorization' => "Bearer #{@api_key}",
        'Content-Type'  => 'application/json'
      }
    end

    def build_http(uri)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      unless @http_timeout.nil?
        http.open_timeout = @http_timeout
        http.read_timeout = @http_timeout
      end
      http
    end

    def request(method, path, payload = nil)
      uri  = URI.parse("#{@base_url}#{path}")
      http = build_http(uri)

      req = case method
            when :get  then Net::HTTP::Get.new(uri.request_uri)
            when :post then Net::HTTP::Post.new(uri.request_uri)
            end

      auth_headers.each { |k, v| req[k] = v }
      req.body = JSON.generate(payload) if payload

      resp         = http.request(req)
      content_type = resp['content-type'] || ''

      body = if content_type.include?('application/json')
               JSON.parse(resp.body)
             else
               resp.body
             end

      return body if resp.code.to_i.between?(200, 299)

      message = body.is_a?(Hash) && body['error'] ? body['error'] : "HTTP #{resp.code}"
      raise ApiError.new(message, resp.code.to_i, body)
    end

    def encode_path_segment(str)
      str.gsub(/[^A-Za-z0-9\-._~]/) { |c| c.bytes.map { |b| format('%%%02X', b) }.join }
    end

    def parse_share(s)
      Share.new(
        type:            s['type'],
        file_name:       s['file_name'],
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
