module Konfidant
  class ApiError < StandardError
    attr_reader :status_code, :body

    def initialize(message, status_code, body)
      super(message)
      @status_code = status_code
      @body        = body
    end
  end
end
