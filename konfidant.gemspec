require_relative 'lib/konfidant/version'

Gem::Specification.new do |spec|
  spec.name     = 'konfidant'
  spec.version  = Konfidant::VERSION
  spec.authors  = ['Konfidant']
  spec.email    = ['hello@konfidant.app']
  spec.summary  = 'Official Ruby SDK for the Konfidant API'
  spec.homepage = 'https://github.com/konfidant/sdk-ruby'
  spec.license  = 'MIT'

  spec.required_ruby_version = '>= 3.2.0'

  spec.files         = Dir['lib/**/*', 'LICENSE', 'README.md']
  spec.require_paths = ['lib']

  spec.add_development_dependency 'rspec',   '~> 3.13'
  spec.add_development_dependency 'webmock', '~> 3.23'
end
