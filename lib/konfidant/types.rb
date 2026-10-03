module Konfidant
  # Result of Client#share_text. +share_url+ carries the decryption key in its fragment — treat it as a secret.
  TextShare = Data.define(:share_url, :text_id, :expires_at)

  # Result of Client#share_file. +share_url+ carries the decryption key in its fragment — treat it as a secret.
  FileShare = Data.define(:share_url, :file_id, :expires_at, :verified_burn)

  # Result of Client#create_file_upload. +ciphertext_size+ is the size declared to the server (echoed client-side).
  FileUpload = Data.define(:upload_url, :file_key, :upload_headers, :upload_expires_in, :ciphertext_size)

  # Result of Client#complete_file_upload. +download_url+ holds only the token (#t=…); append the key with
  # Konfidant::Knf.build_share_url to obtain a usable share link.
  CompletedUpload = Data.define(:download_url, :file_id, :expires_at, :verified_burn)

  # Result of Client#open_share. +kind+ is "text" or "file"; +data+ is binary; +text+ is set for text shares only.
  OpenedShare = Data.define(:kind, :name, :mime, :data, :text)

  Share = Data.define(:type, :file_size_bytes, :created_at, :expires_at, :accessed_at, :created_by) do
    def initialize(type:, created_at:, expires_at:, file_size_bytes: nil, accessed_at: nil, created_by: nil)
      super
    end
  end

  Pagination = Data.define(:total, :limit, :offset, :has_more)

  ListSharesResponse = Data.define(:shares, :pagination)
end
