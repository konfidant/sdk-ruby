module Konfidant
  # Base class for every error raised by this SDK.
  class Error < StandardError; end

  # Raised for non-2xx responses from the Konfidant API, the upload URL or the download endpoint.
  class ApiError < Error
    attr_reader :status_code, :body

    def initialize(message, status_code, body)
      super(message)
      @status_code = status_code
      @body        = body
    end
  end

  # Raised when KNF1 encryption or decryption fails: invalid input, wrong key, or modified/truncated ciphertext.
  class KnfError < Error; end
end
