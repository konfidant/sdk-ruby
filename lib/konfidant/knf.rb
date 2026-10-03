require 'openssl'
require 'securerandom'
require 'stringio'
require 'uri'

module Konfidant
  # KNF1 — Konfidant client-side encryption format.
  #
  # Content is encrypted on the sender's machine with a random 256-bit key that travels only in the share link's
  # URL fragment, so Konfidant's servers store and deliver ciphertext they cannot decrypt.
  #
  #   ciphertext = header (16 bytes) || sealed_chunk_0 || ... || sealed_chunk_n
  #   stream     = uint32_be(len(meta)) || meta || content
  #   meta       = kind (1) || uint16_be(len(name)) || name || uint16_be(len(mime)) || mime
  #   nonce_i    = nonce_prefix (7) || uint32_be(i) || last_flag (1)
  #
  # Every chunk is sealed with AES-256-GCM (16-byte tag) and authenticates the header as AAD.
  # All byte strings produced and consumed here are binary (ASCII-8BIT).
  module Knf
    MAGIC              = 'KNF1'.b.freeze
    HEADER_SIZE        = 16
    TAG_SIZE           = 16
    KEY_SIZE           = 32
    NONCE_PREFIX_SIZE  = 7
    DEFAULT_CHUNK_SIZE = 1024 * 1024
    MIN_CHUNK_SIZE     = 4096
    MAX_CHUNK_SIZE     = 16 * 1024 * 1024
    MAX_NAME_BYTES     = 1024
    MAX_MIME_BYTES     = 255
    MAX_CHUNK_INDEX    = 0xFFFFFFFF

    KIND_TEXT          = 1
    KIND_FILE          = 2
    KINDS              = { 'text' => KIND_TEXT, 'file' => KIND_FILE }.freeze
    META_FIXED_SIZE    = 5 # kind (1) + name length (2) + mime length (2)
    META_LENGTH_PREFIX = 4
    CIPHER             = 'aes-256-gcm'.freeze
    KEY_PATTERN        = /\A[A-Za-z0-9_-]{43}\z/

    # Result of a successful decryption. +data+ is a binary String; +kind+ is "text" or "file".
    Decrypted = Data.define(:kind, :name, :mime, :data) do
      # Content of a text share as a UTF-8 String.
      def text
        raise KnfError, 'Share is not a text share' unless kind == 'text'

        Knf.send(:utf8_string, data, 'Text')
      end
    end

    module_function

    # 32 random bytes from the OS CSPRNG. Use a fresh key for every share.
    def generate_key
      SecureRandom.random_bytes(KEY_SIZE)
    end

    # Unpadded base64url (43 characters), as carried in the share link's +k+ fragment parameter.
    def encode_key(key)
      check_key!(key)
      [key].pack('m0').tr('+/', '-_').delete('=')
    end

    def decode_key(encoded)
      raise KnfError, 'Invalid key encoding' unless encoded.is_a?(String) && KEY_PATTERN.match?(encoded)

      key = "#{encoded.tr('-_', '+/')}=".unpack1('m0')
      raise KnfError, 'Invalid key length' unless key.bytesize == KEY_SIZE

      key
    rescue ArgumentError
      raise KnfError, 'Invalid key encoding'
    end

    # Encodes the metadata block. +kind+ is "text" or "file"; texts carry no name or MIME type.
    def encode_metadata(kind:, name: '', mime: '')
      kind_byte = KINDS.fetch(kind.to_s) { raise KnfError, "Unknown content kind: #{kind.inspect}" }
      name_bytes = utf8_bytes(name, 'File name')
      mime_bytes = utf8_bytes(mime, 'MIME type')
      if kind_byte == KIND_TEXT && !(name_bytes.empty? && mime_bytes.empty?)
        raise KnfError, 'Text shares must not carry a name or MIME type'
      end
      raise KnfError, "File name exceeds #{MAX_NAME_BYTES} bytes" if name_bytes.bytesize > MAX_NAME_BYTES
      raise KnfError, "MIME type exceeds #{MAX_MIME_BYTES} bytes" if mime_bytes.bytesize > MAX_MIME_BYTES

      [kind_byte, name_bytes.bytesize].pack('Cn') + name_bytes + [mime_bytes.bytesize].pack('n') + mime_bytes
    end

    # Exact ciphertext size for a metadata block of +metadata_length+ bytes and +content_length+ content bytes.
    def ciphertext_size(metadata_length:, content_length:, chunk_size: DEFAULT_CHUNK_SIZE)
      stream_length = META_LENGTH_PREFIX + metadata_length + content_length
      HEADER_SIZE + stream_length + (TAG_SIZE * ((stream_length + chunk_size - 1) / chunk_size))
    end

    # Largest ciphertext a file share of at most +max_content_bytes+ can produce (longest name and MIME type).
    def max_file_ciphertext_size(max_content_bytes)
      ciphertext_size(metadata_length: META_FIXED_SIZE + MAX_NAME_BYTES + MAX_MIME_BYTES,
                      content_length: max_content_bytes)
    end

    # Largest ciphertext a text share of at most +max_text_bytes+ UTF-8 bytes can produce.
    def max_text_ciphertext_size(max_text_bytes)
      ciphertext_size(metadata_length: META_FIXED_SIZE, content_length: max_text_bytes)
    end

    # Returns a streaming, IO-like Encryptor (responds to #read, #readpartial and #size) that yields the KNF1
    # ciphertext chunk by chunk, so large inputs never have to be held in memory.
    #
    # +content+ is a String (any encoding; its bytes are used) or a readable IO. IOs that respond to #size and #pos
    # (File, Tempfile, StringIO) are streamed from their current position; other IOs are read into memory first.
    #
    # +nonce_prefix+ exists for test vectors only. Never pass it in production.
    def encryptor(key:, content:, kind:, name: '', mime: '', chunk_size: DEFAULT_CHUNK_SIZE, nonce_prefix: nil)
      Encryptor.new(key: key, content: content, metadata: encode_metadata(kind: kind, name: name, mime: mime),
                    chunk_size: chunk_size, nonce_prefix: nonce_prefix)
    end

    # Encrypts +content+ and returns the complete KNF1 ciphertext as a binary String.
    def encrypt(key:, content:, kind:, name: '', mime: '', chunk_size: DEFAULT_CHUNK_SIZE, nonce_prefix: nil)
      encryptor(key: key, content: content, kind: kind, name: name, mime: mime,
                chunk_size: chunk_size, nonce_prefix: nonce_prefix).read
    end

    def encrypt_text(key:, text:, chunk_size: DEFAULT_CHUNK_SIZE, nonce_prefix: nil)
      encrypt(key: key, content: utf8_bytes(text, 'Text'), kind: 'text',
              chunk_size: chunk_size, nonce_prefix: nonce_prefix)
    end

    # Decrypts a complete KNF1 ciphertext. Raises KnfError on any format or authentication failure.
    def decrypt(key:, ciphertext:)
      decryptor = Decryptor.new(key: key)
      decryptor.push(ciphertext)
      decryptor.finish
    end

    # True when +bytes+ starts with a well-formed KNF1 header followed by at least one tag's worth of data.
    def valid_header?(bytes)
      bytes = bytes.b
      return false if bytes.bytesize < HEADER_SIZE + TAG_SIZE

      parse_header(bytes.byteslice(0, HEADER_SIZE))
      true
    rescue KnfError
      false
    end

    # Builds the share link from the server-issued download URL (already carrying "#t=<token>") and the key.
    def build_share_url(download_url, key)
      "#{download_url}&k=#{encode_key(key)}"
    end

    # Parses "#t=<token>&k=<key>" from a share link. Returns [origin, token, key] or raises ArgumentError.
    def parse_share_url(share_url)
      uri = URI.parse(share_url.to_s)
      raise ArgumentError, 'Share URL must be an absolute http(s) URL' unless uri.is_a?(URI::HTTP) && uri.host

      params = URI.decode_www_form(uri.fragment.to_s).to_h
      token = params['t']
      encoded_key = params['k']
      raise ArgumentError, 'Share URL is missing the token (t) or key (k)' if blank?(token) || blank?(encoded_key)

      origin = "#{uri.scheme}://#{uri.host}"
      origin += ":#{uri.port}" unless uri.port == uri.default_port
      [origin, token, decode_key(encoded_key)]
    rescue URI::InvalidURIError
      raise ArgumentError, 'Invalid share URL'
    end

    # --- internal helpers --------------------------------------------------------------------------------------

    def check_key!(key)
      raise KnfError, 'Key must be 32 bytes' unless key.is_a?(String) && key.bytesize == KEY_SIZE
    end

    def check_chunk_size!(chunk_size)
      return if chunk_size.is_a?(Integer) && chunk_size.between?(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE)

      raise KnfError, 'Invalid chunk size'
    end

    def build_header(chunk_size, nonce_prefix)
      MAGIC + [chunk_size].pack('N') + nonce_prefix + "\x00".b
    end

    # Validates a 16-byte header and returns [chunk_size, nonce_prefix].
    def parse_header(header)
      raise KnfError, 'Not a KNF1 payload' unless header.byteslice(0, 4) == MAGIC && header.getbyte(15).zero?

      chunk_size = header.byteslice(4, 4).unpack1('N')
      check_chunk_size!(chunk_size)
      [chunk_size, header.byteslice(8, NONCE_PREFIX_SIZE)]
    end

    def chunk_nonce(nonce_prefix, index, last)
      raise KnfError, 'Too many chunks' if index > MAX_CHUNK_INDEX

      nonce_prefix + [index, last ? 1 : 0].pack('NC')
    end

    def seal(key, nonce, header, plaintext)
      cipher = OpenSSL::Cipher.new(CIPHER).encrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.auth_data = header
      sealed = cipher.update(plaintext) + cipher.final
      sealed << cipher.auth_tag(TAG_SIZE)
      sealed.b
    end

    def open_sealed(key, nonce, header, sealed)
      cipher = OpenSSL::Cipher.new(CIPHER).decrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.auth_tag = sealed.byteslice(-TAG_SIZE, TAG_SIZE)
      cipher.auth_data = header
      (cipher.update(sealed.byteslice(0, sealed.bytesize - TAG_SIZE)) + cipher.final).b
    rescue OpenSSL::Cipher::CipherError
      raise KnfError, 'Decryption failed: wrong key or corrupted or truncated ciphertext'
    end

    def decode_stream(stream)
      raise KnfError, 'Metadata truncated' if stream.bytesize < META_LENGTH_PREFIX

      meta_length = stream.byteslice(0, META_LENGTH_PREFIX).unpack1('N')
      raise KnfError, 'Metadata truncated' if META_LENGTH_PREFIX + meta_length > stream.bytesize

      meta = stream.byteslice(META_LENGTH_PREFIX, meta_length)
      kind, name, mime = decode_metadata(meta)
      data = stream.byteslice((META_LENGTH_PREFIX + meta_length)..) || ''.b
      Decrypted.new(kind: kind, name: name, mime: mime, data: data.b)
    end

    def decode_metadata(meta)
      raise KnfError, 'Metadata truncated' if meta.bytesize < META_FIXED_SIZE

      kind = KINDS.key(meta.getbyte(0))
      raise KnfError, 'Unknown content kind' unless kind

      name_length = meta.byteslice(1, 2).unpack1('n')
      raise KnfError, 'Metadata truncated' if 3 + name_length + 2 > meta.bytesize

      mime_length = meta.byteslice(3 + name_length, 2).unpack1('n')
      raise KnfError, 'Metadata length mismatch' unless META_FIXED_SIZE + name_length + mime_length == meta.bytesize

      [kind,
       utf8_string(meta.byteslice(3, name_length), 'File name'),
       utf8_string(meta.byteslice(5 + name_length, mime_length), 'MIME type')]
    end

    # Converts +value+ to its UTF-8 bytes (binary String). Binary strings are taken as UTF-8 bytes.
    def utf8_bytes(value, label)
      str = value.to_s
      str = str.encoding == Encoding::BINARY ? str.dup.force_encoding(Encoding::UTF_8) : str.encode(Encoding::UTF_8)
      raise KnfError, "#{label} must be valid UTF-8" unless str.valid_encoding?

      str.b
    rescue EncodingError
      raise KnfError, "#{label} must be valid UTF-8"
    end

    def utf8_string(bytes, label)
      str = bytes.dup.force_encoding(Encoding::UTF_8)
      raise KnfError, "#{label} is not valid UTF-8" unless str.valid_encoding?

      str
    end

    def blank?(value)
      value.nil? || value.empty?
    end

    private_class_method :check_key!, :check_chunk_size!, :build_header, :parse_header, :chunk_nonce, :seal,
                         :open_sealed, :decode_stream, :decode_metadata, :utf8_bytes, :utf8_string, :blank?

    # Streaming KNF1 encryptor with an IO-like read interface. #size is the exact ciphertext length, known up front
    # so it can be declared to the server (ciphertext_size) and sent as Content-Length.
    class Encryptor
      attr_reader :size

      def initialize(key:, content:, metadata:, chunk_size: DEFAULT_CHUNK_SIZE, nonce_prefix: nil)
        Knf.send(:check_key!, key)
        Knf.send(:check_chunk_size!, chunk_size)
        nonce_prefix = nonce_prefix ? nonce_prefix.b : SecureRandom.random_bytes(NONCE_PREFIX_SIZE)
        raise KnfError, 'Nonce prefix must be 7 bytes' unless nonce_prefix.bytesize == NONCE_PREFIX_SIZE

        @key          = key.b
        @chunk_size   = chunk_size
        @nonce_prefix = nonce_prefix
        @source, content_length = normalize_source(content)
        @prefix       = [metadata.bytesize].pack('N') + metadata
        @remaining    = @prefix.bytesize + content_length
        @chunk_count  = (@remaining + chunk_size - 1) / chunk_size
        raise KnfError, 'Too many chunks' if @chunk_count - 1 > MAX_CHUNK_INDEX

        @header = Knf.send(:build_header, chunk_size, nonce_prefix)
        @size   = Knf.ciphertext_size(metadata_length: metadata.bytesize, content_length: content_length,
                                      chunk_size: chunk_size)
        @index  = 0
        @buffer = @header.dup
      end

      # IO#read semantics: without +length+ returns everything left ("" at EOF); with +length+ returns up to
      # +length+ bytes, or nil at EOF.
      def read(length = nil, outbuf = nil)
        if length.nil?
          fill(Float::INFINITY)
          data = take(@buffer.bytesize)
        else
          raise ArgumentError, "negative length #{length} given" if length.negative?

          fill(length)
          return replace(outbuf, ''.b) if length.zero?
          return replace(outbuf, nil) if @buffer.empty?

          data = take([length, @buffer.bytesize].min)
        end
        replace(outbuf, data)
      end

      def readpartial(length, outbuf = nil)
        data = read(length, outbuf)
        raise EOFError, 'end of file reached' if data.nil?

        data
      end

      def eof?
        @buffer.empty? && @index >= @chunk_count
      end

      private

      def normalize_source(content)
        case content
        when String
          bytes = content.b
          [StringIO.new(bytes), bytes.bytesize]
        else
          raise ArgumentError, 'content must be a String or a readable IO' unless content.respond_to?(:read)

          if content.respond_to?(:size) && content.respond_to?(:pos)
            [content, content.size - content.pos]
          else
            bytes = (content.read || '').b
            [StringIO.new(bytes), bytes.bytesize]
          end
        end
      end

      def fill(length)
        @buffer << next_sealed_chunk while @buffer.bytesize < length && @index < @chunk_count
      end

      def take(length)
        data = @buffer.byteslice(0, length)
        @buffer = @buffer.byteslice(length..) || ''.b
        data
      end

      def replace(outbuf, data)
        return data if outbuf.nil?

        outbuf.replace(data || ''.b)
        data && outbuf
      end

      def next_sealed_chunk
        length = [@chunk_size, @remaining].min
        chunk = ''.b
        unless @prefix.empty?
          chunk << @prefix.byteslice(0, length)
          @prefix = @prefix.byteslice(length..) || ''.b
        end
        chunk << read_source(length - chunk.bytesize)
        @remaining -= length
        last = @index == @chunk_count - 1
        ensure_source_exhausted if last

        nonce = Knf.send(:chunk_nonce, @nonce_prefix, @index, last)
        @index += 1
        Knf.send(:seal, @key, nonce, @header, chunk)
      end

      def read_source(length)
        data = ''.b
        while data.bytesize < length
          part = @source.read(length - data.bytesize)
          raise KnfError, 'Content is shorter than its declared size' if part.nil? || part.empty?

          data << part.b
        end
        data
      end

      def ensure_source_exhausted
        extra = @source.read(1)
        raise KnfError, 'Content is longer than its declared size' unless extra.nil? || extra.empty?
      end
    end

    # Incremental decryptor: #push bytes as they arrive, then #finish. A full-size chunk is only opened once more
    # data has arrived, because the final chunk is authenticated with the "last" flag — this detects truncation.
    class Decryptor
      def initialize(key:)
        Knf.send(:check_key!, key)
        @key       = key.b
        @header    = nil
        @buffer    = ''.b
        @plaintext = ''.b
        @index     = 0
        @finished  = false
      end

      def push(bytes)
        raise KnfError, 'Decryptor already finished' if @finished

        @buffer << bytes.b
        return self unless header_ready?

        sealed_size = @chunk_size + TAG_SIZE
        offset = 0
        # Keep at least one byte beyond a full chunk before opening it as non-final.
        while @buffer.bytesize - offset > sealed_size
          open_chunk(@buffer.byteslice(offset, sealed_size), last: false)
          offset += sealed_size
        end
        @buffer = @buffer.byteslice(offset..) if offset.positive?
        self
      end

      # Opens the final chunk and returns Knf::Decrypted. Raises KnfError if the ciphertext is truncated.
      def finish
        raise KnfError, 'Decryptor already finished' if @finished
        raise KnfError, 'Ciphertext truncated' if @header.nil? || @buffer.bytesize <= TAG_SIZE

        open_chunk(@buffer, last: true)
        @finished = true
        @buffer = ''.b
        stream = @plaintext
        @plaintext = ''.b
        Knf.send(:decode_stream, stream)
      end

      private

      def header_ready?
        return true if @header
        return false if @buffer.bytesize < HEADER_SIZE

        header = @buffer.byteslice(0, HEADER_SIZE)
        @chunk_size, @nonce_prefix = Knf.send(:parse_header, header)
        @header = header
        @buffer = @buffer.byteslice(HEADER_SIZE..)
        true
      end

      def open_chunk(sealed, last:)
        nonce = Knf.send(:chunk_nonce, @nonce_prefix, @index, last)
        @plaintext << Knf.send(:open_sealed, @key, nonce, @header, sealed)
        @index += 1
      rescue KnfError
        # Any authentication failure is fatal: discard everything decrypted so far.
        @plaintext = ''.b
        @buffer = ''.b
        @finished = true
        raise
      end
    end
  end
end
