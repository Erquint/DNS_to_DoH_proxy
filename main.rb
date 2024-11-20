# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require 'net/http'
require 'resolv'
require 'socket'

require_relative 'constants'
require_relative 'overloads'
require_relative 'logging'
require_relative 'doh_client'
require_relative 'dns_server'

# require_relative 'devlibs\Hyperspector\Hyperspector'

doh_full_address = ARGV[0]
re_match = doh_full_address.match(/(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?(?!\d)/)
doh_address = re_match[1]
doh_port = (re_match[2] || DNS_to_DoH_proxy::Defaults[:doh_port]).to_i()

socket = UDPSocket.new()
socket.connect('192.168.0.1', 0)
local_address = socket.local_address().ip_address()
socket.close()
local_address_arpa = "#{local_address.split('.').reverse().join('.')}.in-addr.arpa"

DNS_to_DoH_proxy::serve_dns_doh_proxy(
  dns_address: '0.0.0.0',
  doh_address: doh_address,
  doh_port: doh_port,
  local_address_arpa: local_address_arpa
)

__END__
To do:
stop sercvices

References:
RFC 1035 : Domain Implementation and Specification : November 1987
RFC 8484 : DNS Queries over HTTPS (DoH) : October 2018
