# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require 'net/http'
require 'resolv'
require 'socket'
# require 'G:\Projects\rb\Hyperspector\Hyperspector.rb'

OPCODE_ENUM = {
  0 =>  'A standard query (QUERY)',
  1 =>  'An inverse query (IQUERY)',
  2 =>  'A server status request (STATUS)',
  3 =>  'Reserved for future use',
  4 =>  'Reserved for future use',
  5 =>  'Reserved for future use',
  6 =>  'Reserved for future use',
  7 =>  'Reserved for future use',
  8 =>  'Reserved for future use',
  9 =>  'Reserved for future use',
  10 => 'Reserved for future use',
  11 => 'Reserved for future use',
  12 => 'Reserved for future use',
  13 => 'Reserved for future use',
  14 => 'Reserved for future use',
  15 => 'Reserved for future use'
}

RCODE_ENUM = {
  0 =>  'No error condition.',
  1 =>  'Format error - The name server was unable to interpret the query.',
  2 =>  'Server failure - The name server was unable to process this query due to a problem with the name server.',
  3 =>  'Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.',
  4 =>  'Not Implemented - The name server does not support the requested kind of query.',
  5 =>  'Refused - The name server refuses to perform the specified operation for policy reasons.  For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.',
  6 =>  'Reserved for future use',
  7 =>  'Reserved for future use',
  8 =>  'Reserved for future use',
  9 =>  'Reserved for future use',
  10 => 'Reserved for future use',
  11 => 'Reserved for future use',
  12 => 'Reserved for future use',
  13 => 'Reserved for future use',
  14 => 'Reserved for future use',
  15 => 'Reserved for future use'
}

Defaults = {
  doh_address: '1.1.1.1',
  doh_port: 443,
  dns_address: '0.0.0.0',
  dns_port: 53,
  path: '/dns-query',
  parameter: 'dns',
  doh_post_headers: {
    'Content-Type' => 'application/dns-message',
    'Accept' => 'application/dns-message'
  },
  local_address_arpa: '100.0.168.192.in-addr.arpa'
}

def serve_dns_doh_proxy(
    dns_address: Defaults[:dns_address],
    dns_port: Defaults[:dns_port],
    doh_address: Defaults[:doh_address],
    doh_port: Defaults[:doh_port],
    local_address_arpa: Defaults[:local_address_arpa]
  )
  
    socket = UDPSocket.new()
    socket.bind(dns_address, dns_port)
    doh_connection = Net::HTTP.new(?*, doh_port)
    doh_connection.use_ssl = true
    doh_connection.ssl_version = :TLSv1_2
    doh_connection.verify_hostname = false
    doh_connection.ipaddr = doh_address
    
    while (dns_message, sender_addrinfo = socket.recvfrom(512)).first() do
      socket.send(doh_connection.post(Defaults[:path], dns_message, Defaults[:doh_post_headers]).body(), 0, sender_addrinfo[3], sender_addrinfo[1])
    end
end

doh_full_address = ARGV[0]
re_match = doh_full_address.match(/(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?(?!\d)/)
doh_address = re_match[1]
doh_port = (re_match[2] || Defaults[:doh_port]).to_i()
socket = UDPSocket.new()
socket.connect('192.168.0.1', 0)
local_address = socket.local_address().ip_address()
socket.close()
local_address_arpa = "#{local_address.split('.').reverse().join('.')}.in-addr.arpa"
serve_dns_doh_proxy(
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
