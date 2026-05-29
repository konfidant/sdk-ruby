module Konfidant
  FileMetadataHeaders = Data.define(:user_id, :ttl_hours, :organization_id)

  ShareTextResponse = Data.define(:text_id, :share_url, :expires_at, :verified_burn)

  ShareFileResponse = Data.define(:upload_url, :file_key, :metadata_headers, :poll_url)

  FileStatusResponse = Data.define(
    :status, :message, :file_id, :file_name, :share_url, :expires_at, :verified_burn
  ) do
    def initialize(status:, message: nil, file_id: nil, file_name: nil,
                   share_url: nil, expires_at: nil, verified_burn: nil)
      super
    end
  end

  Share = Data.define(
    :type, :file_name, :file_size_bytes, :created_at, :expires_at, :accessed_at, :created_by
  ) do
    def initialize(type:, file_name:, file_size_bytes:, created_at:,
                   expires_at:, created_by:, accessed_at: nil)
      super
    end
  end

  Pagination = Data.define(:total, :limit, :offset, :has_more)

  ListSharesResponse = Data.define(:shares, :pagination)

  ShareResult = Data.define(:share_url, :file_id, :expires_at, :verified_burn)
end
