# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |gem|
  gem.name          = "mctop"
  gem.version       = "0.0.4"
  gem.authors       = ["Marcus Barczak"]
  gem.email         = ["marcus@etsy.com"]
  gem.description   = %q{mctop - a realtime memcache key analyzer}
  gem.summary       = %q{mctop - an interactive terminal app for analyzing memcache key activity breaking it out by requests per second, calls, and estimated bandwidth make sure you have the libpcap development libraries installed for the dependencies}
  gem.homepage      = "https://github.com/etsy/mctop/"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.require_paths = ["lib"]

  gem.add_runtime_dependency 'ruby-pcap', '= 0.7.9'
  gem.add_runtime_dependency 'curses', '~> 1.0.1'
end
