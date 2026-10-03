require 'json'
require 'tempfile'

RSpec.describe Konfidant::Knf do
  let(:key) { Konfidant::Knf.generate_key }

  def unhex(hex)
    [hex].pack('H*')
  end

  describe 'test vectors' do
    vectors = JSON.parse(File.read(File.expand_path('../fixtures/knf1-test-vectors.json', __dir__)))

    it 'is a KNF1 vector file' do
      expect(vectors['format']).to eq('KNF1')
      expect(vectors['vectors']).not_to be_empty
    end

    vectors['vectors'].each do |v|
      context v['name'] do
        let(:vkey)      { unhex(v['key_hex']) }
        let(:plaintext) { unhex(v['plaintext_hex']) }
        let(:expected)  { unhex(v['ciphertext_hex']) }
        let(:options) do
          { key: vkey, kind: v['kind'], name: v['file_name'], mime: v['mime'],
            chunk_size: v['chunk_size'], nonce_prefix: unhex(v['nonce_prefix_hex']) }
        end

        it 'reproduces the ciphertext byte for byte from a String' do
          ciphertext = described_class.encrypt(content: plaintext, **options)
          expect(ciphertext.encoding).to eq(Encoding::BINARY)
          expect(ciphertext.unpack1('H*')).to eq(v['ciphertext_hex'])
        end

        it 'reproduces the ciphertext byte for byte from an IO read in small pieces' do
          encryptor = described_class.encryptor(content: StringIO.new(plaintext), **options)
          expect(encryptor.size).to eq(expected.bytesize)
          out = ''.b
          while (part = encryptor.read(1000))
            out << part
          end
          expect(out).to eq(expected)
        end

        it 'predicts the ciphertext size' do
          meta = described_class.encode_metadata(kind: v['kind'], name: v['file_name'], mime: v['mime'])
          size = described_class.ciphertext_size(metadata_length: meta.bytesize, content_length: plaintext.bytesize,
                                                 chunk_size: v['chunk_size'])
          expect(size).to eq(expected.bytesize)
        end

        it 'decrypts the ciphertext' do
          result = described_class.decrypt(key: vkey, ciphertext: expected)
          expect(result.kind).to eq(v['kind'])
          expect(result.name).to eq(v['file_name'])
          expect(result.mime).to eq(v['mime'])
          expect(result.data).to eq(plaintext)
          expect(result.data.encoding).to eq(Encoding::BINARY)
          expect(result.name.encoding).to eq(Encoding::UTF_8)
        end

        it 'decrypts the ciphertext when streamed byte-range by byte-range' do
          decryptor = described_class::Decryptor.new(key: vkey)
          expected.bytes.each_slice(777) { |slice| decryptor.push(slice.pack('C*')) }
          expect(decryptor.finish.data).to eq(plaintext)
        end

        it 'encodes and decodes the key' do
          expect(described_class.encode_key(vkey)).to eq(v['key_b64url'])
          expect(described_class.decode_key(v['key_b64url'])).to eq(vkey)
        end
      end
    end

    it 'decrypts the short text vector to its UTF-8 text' do
      v = vectors['vectors'].find { |x| x['name'] == 'text-short' }
      result = described_class.decrypt(key: unhex(v['key_hex']), ciphertext: unhex(v['ciphertext_hex']))
      expect(result.text).to eq("Hello, Konfidant! \u{1F510}")
      expect(result.text.encoding).to eq(Encoding::UTF_8)
    end
  end

  describe 'round trip' do
    let(:content) { Random.new(42).bytes(50_000) }

    it 'round-trips multi-chunk binary content' do
      ciphertext = described_class.encrypt(key: key, content: content, kind: 'file', name: 'blob.bin',
                                           mime: 'application/octet-stream', chunk_size: 4096)
      expect(ciphertext.bytesize).to eq(16 + 4 + 5 + 8 + 24 + 50_000 + (16 * 13))
      result = described_class.decrypt(key: key, ciphertext: ciphertext)
      expect(result.data).to eq(content)
      expect(result.name).to eq('blob.bin')
    end

    it 'streams from a File at its current position' do
      Tempfile.create(['knf', '.bin'], binmode: true) do |f|
        f.write("SKIP#{content}")
        f.flush
        f.rewind
        f.read(4)
        encryptor = described_class.encryptor(key: key, content: f, kind: 'file', name: 'x', chunk_size: 4096)
        ciphertext = encryptor.read
        expect(ciphertext.bytesize).to eq(encryptor.size)
        expect(described_class.decrypt(key: key, ciphertext: ciphertext).data).to eq(content)
      end
    end

    it 'reads IOs without a size into memory' do
      reader, writer = IO.pipe
      writer.write(content)
      writer.close
      ciphertext = described_class.encrypt(key: key, content: reader, kind: 'file', chunk_size: 4096)
      expect(described_class.decrypt(key: key, ciphertext: ciphertext).data).to eq(content)
    ensure
      reader&.close
    end

    it 'uses a random nonce prefix per encryption' do
      a = described_class.encrypt(key: key, content: 'same', kind: 'file')
      b = described_class.encrypt(key: key, content: 'same', kind: 'file')
      expect(a.byteslice(8, 7)).not_to eq(b.byteslice(8, 7))
    end

    it 'treats strings in any encoding as their bytes' do
      text = 'Grüße'.encode('ISO-8859-1')
      ciphertext = described_class.encrypt(key: key, content: text, kind: 'file')
      expect(described_class.decrypt(key: key, ciphertext: ciphertext).data).to eq(text.b)
    end

    it 'encodes text as UTF-8' do
      ciphertext = described_class.encrypt_text(key: key, text: 'Grüße'.encode('ISO-8859-1'))
      expect(described_class.decrypt(key: key, ciphertext: ciphertext).text).to eq('Grüße')
    end

    it 'rejects text that is not valid UTF-8' do
      expect { described_class.encrypt_text(key: key, text: "\xFF".b) }
        .to raise_error(Konfidant::KnfError, /UTF-8/)
    end

    it 'supports IO-like read with an output buffer and readpartial' do
      encryptor = described_class.encryptor(key: key, content: 'abc', kind: 'file')
      buf = +''
      expect(encryptor.read(0)).to eq('')
      expect(encryptor.read(4, buf)).to equal(buf)
      expect(buf.bytesize).to eq(4)
      rest = encryptor.readpartial(10_000)
      expect(4 + rest.bytesize).to eq(encryptor.size)
      expect(encryptor).to be_eof
      expect(encryptor.read(1)).to be_nil
      expect(encryptor.read).to eq('')
      expect { encryptor.readpartial(1) }.to raise_error(EOFError)
    end

    it 'rejects content that shrinks after its size was taken' do
      io = StringIO.new('x' * 10)
      encryptor = described_class.encryptor(key: key, content: io, kind: 'file')
      io.truncate(5)
      expect { encryptor.read }.to raise_error(Konfidant::KnfError, /shorter/)
    end

    it 'rejects content that grows after its size was taken' do
      io = StringIO.new('x' * 10)
      encryptor = described_class.encryptor(key: key, content: io, kind: 'file')
      io.string << 'more'
      expect { encryptor.read }.to raise_error(Konfidant::KnfError, /longer/)
    end

    it 'rejects content that is neither String nor IO' do
      expect { described_class.encrypt(key: key, content: 42, kind: 'file') }.to raise_error(ArgumentError)
    end
  end

  describe 'tamper detection' do
    let(:content)    { Random.new(7).bytes(10_000) }
    let(:ciphertext) { described_class.encrypt(key: key, content: content, kind: 'file', chunk_size: 4096) }
    let(:sealed)     { 4096 + 16 }

    def expect_failure(bytes, decrypt_key = key)
      expect { described_class.decrypt(key: decrypt_key, ciphertext: bytes) }.to raise_error(Konfidant::KnfError)
    end

    it 'rejects a wrong key' do
      expect_failure(ciphertext, described_class.generate_key)
    end

    it 'rejects a flipped bit in every region' do
      [16, 16 + sealed - 1, 16 + sealed + 5, ciphertext.bytesize - 1].each do |pos|
        tampered = ciphertext.dup
        tampered.setbyte(pos, tampered.getbyte(pos) ^ 0x01)
        expect_failure(tampered)
      end
    end

    it 'rejects a modified header (authenticated as AAD)' do
      tampered = ciphertext.dup
      tampered.setbyte(8, tampered.getbyte(8) ^ 0x01)
      expect_failure(tampered)
    end

    it 'rejects truncation at a chunk boundary' do
      expect_failure(ciphertext.byteslice(0, 16 + (2 * sealed)))
      expect_failure(ciphertext.byteslice(0, 16 + sealed))
    end

    it 'rejects truncation inside a chunk' do
      expect_failure(ciphertext.byteslice(0, ciphertext.bytesize - 1))
    end

    it 'rejects reordered chunks' do
      chunks = [ciphertext.byteslice(16, sealed), ciphertext.byteslice(16 + sealed, sealed)]
      reordered = ciphertext.byteslice(0, 16) + chunks[1] + chunks[0] + ciphertext.byteslice((16 + (2 * sealed))..)
      expect_failure(reordered)
    end

    it 'rejects a duplicated chunk' do
      dup = ciphertext.byteslice(0, 16 + sealed) + ciphertext.byteslice(16, sealed) + ciphertext.byteslice((16 + sealed)..)
      expect_failure(dup)
    end

    it 'rejects appended data' do
      expect_failure(ciphertext + 'x'.b)
    end

    it 'rejects input shorter than header plus tag' do
      expect_failure(''.b)
      expect_failure(ciphertext.byteslice(0, 10))
      expect_failure(ciphertext.byteslice(0, 32))
    end

    it 'rejects bad magic, reserved byte and chunk size' do
      bad_magic = ciphertext.dup.tap { |c| c.setbyte(0, 0x58) }
      bad_reserved = ciphertext.dup.tap { |c| c.setbyte(15, 1) }
      bad_chunk = "#{ciphertext.byteslice(0, 4)}#{[1024].pack('N')}#{ciphertext.byteslice(8..)}".b
      [bad_magic, bad_reserved, bad_chunk].each { |bytes| expect_failure(bytes) }
    end

    it 'discards output and refuses further use after an authentication failure' do
      tampered = ciphertext.dup
      tampered.setbyte(20, tampered.getbyte(20) ^ 0x01)
      decryptor = described_class::Decryptor.new(key: key)
      expect { decryptor.push(tampered) }.to raise_error(Konfidant::KnfError, /Decryption failed/)
      expect { decryptor.finish }.to raise_error(Konfidant::KnfError)
    end

    it 'rejects malformed metadata even when correctly encrypted' do
      header = "KNF1#{[4096].pack('N')}#{"\x00" * 8}".b
      bad_stream = "#{[5].pack('N')}\x09\x00\x00\x00\x00hi".b
      sealed_chunk = described_class.send(:seal, key, described_class.send(:chunk_nonce, "\x00".b * 7, 0, true),
                                          header, bad_stream)
      expect { described_class.decrypt(key: key, ciphertext: header + sealed_chunk) }
        .to raise_error(Konfidant::KnfError, /Unknown content kind/)
    end
  end

  describe 'metadata limits' do
    it 'accepts a 1024-byte name and a 255-byte MIME type' do
      meta = described_class.encode_metadata(kind: 'file', name: 'é' * 512, mime: 'm' * 255)
      expect(meta.bytesize).to eq(5 + 1024 + 255)
    end

    it 'measures the name limit in UTF-8 bytes' do
      expect { described_class.encode_metadata(kind: 'file', name: "#{'é' * 512}a") }
        .to raise_error(Konfidant::KnfError, /File name exceeds 1024 bytes/)
    end

    it 'rejects a MIME type over 255 bytes' do
      expect { described_class.encode_metadata(kind: 'file', mime: 'm' * 256) }
        .to raise_error(Konfidant::KnfError, /MIME type exceeds 255 bytes/)
    end

    it 'does not allow a name or MIME type on text' do
      expect { described_class.encode_metadata(kind: 'text', name: 'a') }.to raise_error(Konfidant::KnfError)
      expect { described_class.encode_metadata(kind: 'text', mime: 'a') }.to raise_error(Konfidant::KnfError)
    end

    it 'places no size limit on text content' do
      ciphertext = described_class.encrypt_text(key: key, text: 'a' * 3_000_000)
      expect(described_class.decrypt(key: key, ciphertext: ciphertext).text.bytesize).to eq(3_000_000)
    end

    it 'rejects an unknown kind' do
      expect { described_class.encode_metadata(kind: 'video') }.to raise_error(Konfidant::KnfError, /Unknown/)
    end
  end

  describe 'sizes' do
    it 'computes ciphertext_size across chunk counts' do
      expect(described_class.ciphertext_size(metadata_length: 5, content_length: 0)).to eq(16 + 9 + 16)
      expect(described_class.ciphertext_size(metadata_length: 5, content_length: 4087, chunk_size: 4096))
        .to eq(16 + 4096 + 16)
      expect(described_class.ciphertext_size(metadata_length: 5, content_length: 4088, chunk_size: 4096))
        .to eq(16 + 4097 + 32)
    end

    it 'computes the server-side bounds' do
      expect(described_class.max_file_ciphertext_size(100))
        .to eq(described_class.ciphertext_size(metadata_length: 1284, content_length: 100))
      expect(described_class.max_text_ciphertext_size(100))
        .to eq(described_class.ciphertext_size(metadata_length: 5, content_length: 100))
    end

    it 'rejects invalid chunk sizes and nonce prefixes' do
      expect { described_class.encrypt(key: key, content: 'x', kind: 'file', chunk_size: 4095) }
        .to raise_error(Konfidant::KnfError, /chunk size/)
      expect { described_class.encrypt(key: key, content: 'x', kind: 'file', chunk_size: (16 * 1024 * 1024) + 1) }
        .to raise_error(Konfidant::KnfError, /chunk size/)
      expect { described_class.encrypt(key: key, content: 'x', kind: 'file', nonce_prefix: 'short') }
        .to raise_error(Konfidant::KnfError, /Nonce prefix/)
    end

    it 'validates headers' do
      ciphertext = described_class.encrypt(key: key, content: 'x', kind: 'file')
      expect(described_class.valid_header?(ciphertext)).to be(true)
      expect(described_class.valid_header?("XXXX#{ciphertext.byteslice(4..)}")).to be(false)
      expect(described_class.valid_header?(ciphertext.byteslice(0, 20))).to be(false)
    end
  end

  describe 'keys' do
    it 'generates 32 random bytes' do
      expect(key.bytesize).to eq(32)
      expect(key.encoding).to eq(Encoding::BINARY)
      expect(described_class.generate_key).not_to eq(key)
    end

    it 'encodes to 43 unpadded base64url characters' do
      encoded = described_class.encode_key("\xFF".b * 32)
      expect(encoded).to match(/\A[A-Za-z0-9_-]{43}\z/)
      expect(encoded).to include('_')
      expect(described_class.decode_key(encoded)).to eq("\xFF".b * 32)
    end

    it 'rejects malformed keys' do
      ['', 'a' * 42, 'a' * 44, "#{'a' * 42}+", "#{'A' * 42}B", nil].each do |bad|
        expect { described_class.decode_key(bad) }.to raise_error(Konfidant::KnfError)
      end
    end

    it 'rejects keys that are not 32 bytes' do
      expect { described_class.encode_key('short') }.to raise_error(Konfidant::KnfError, /32 bytes/)
      expect { described_class.encrypt(key: 'short', content: 'x', kind: 'file') }.to raise_error(Konfidant::KnfError)
      expect { described_class::Decryptor.new(key: 'short') }.to raise_error(Konfidant::KnfError)
    end
  end

  describe 'share URLs' do
    it 'appends the key to the download URL fragment' do
      url = described_class.build_share_url('https://download.konfidant.app/#t=abc%2Bdef', key)
      expect(url).to eq("https://download.konfidant.app/#t=abc%2Bdef&k=#{described_class.encode_key(key)}")
    end

    it 'parses origin, token and key' do
      url = described_class.build_share_url('https://share.example.com:8443/#t=abc%2Bdef', key)
      expect(described_class.parse_share_url(url)).to eq(['https://share.example.com:8443', 'abc+def', key])
    end

    it 'rejects links without token or key' do
      ['https://download.konfidant.app/#t=abc', 'https://download.konfidant.app/#k=x',
       'https://download.konfidant.app/', 'not a url', '/relative#t=a&k=b'].each do |bad|
        expect { described_class.parse_share_url(bad) }.to raise_error(ArgumentError)
      end
    end

    it 'rejects links with a malformed key' do
      expect { described_class.parse_share_url('https://download.konfidant.app/#t=abc&k=short') }
        .to raise_error(Konfidant::KnfError)
    end
  end
end
