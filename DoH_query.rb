# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require 'net/http'
require 'resolv'
require 'base64'
# require 'G:\Projects\rb\Hyperspector\Hyperspector.rb'

Record_types = {
  ?4 => Resolv::DNS::Resource::IN::A,
  ?6 => Resolv::DNS::Resource::IN::AAAA
}

doh_address = ARGV[0]
queried_hostname = ARGV[1]
record_type = ARGV[2] || ?4
record_type = Record_types[record_type]

Defaults = {
  queried_hostname: 'example.com',
  query_type: Resolv::DNS::Resource::IN::A,
  doh_port: 443,
  doh_address: doh_address,
  path: '/dns-query',
  parameter: 'dns'
}

queried_hostname = Defaults[:queried_hostname]
re_match = doh_address.match(/(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?(?!\d)/)
doh_address = re_match[1]
doh_port = (re_match[2] || Defaults[:doh_port]).to_i()

def wire_codec(
    hostname: Defaults[:queried_hostname],
    type: Defaults[:query_type],
    wire64: nil,
    recursion: true
  )
  if wire64 then
    return Resolv::DNS::Message.decode(wire64)
  else
    message = Resolv::DNS::Message.new()
    message.rd = recursion ? 1 : 0 # Recursion desired
    message.add_question(hostname, type)
    return message.encode()
  end
end

def doh_get_response(connection, wire64_query: nil)
  https_get_options = {'accept' => 'application/dns-message'}
  begin
    return connection.get(Defaults[:path] + ?? + Defaults[:parameter] + ?= +
      wire64_query, https_get_options)
  rescue => exception
    return exception
  end
end

def prepare_connection(
    doh_address: Defaults[:doh_address],
    doh_port: Defaults[:doh_port]
  )
  https_connection = Net::HTTP.new(?*, doh_port)
  https_connection.use_ssl = true
  https_connection.ssl_version = :TLSv1_2
  https_connection.verify_hostname = false
  https_connection.ipaddr = doh_address
  return https_connection
end

def print_doh_response(response)
  raise('TLS connection failed to establish!') if response.is_a?(OpenSSL::SSL::SSLError)
  
  if response.code.to_i == 200
    response = wire_codec(wire64: response.body)
  else
    raise("Failed to query DoH server: #{response.code} #{response.message}!")
  end
  
  puts('Requests:')
  response.question.each() do |question|
    question.each() do |field|
      puts("  Hostname:\n    #{field}") if field.is_a?(Resolv::DNS::Name)
      puts("  Class:\n    #{field.to_s().split(?:).last()}") if field.is_a?(Class)
    end
  end
  
  puts('Responses:')
  response.answer.each() do |answer|
    answer.each() do |field|
      puts("  Address:\n    #{field.address()}") if field.respond_to?(:address)
      puts("  TTL:\n    #{field.ttl()}") if field.respond_to?(:ttl)
    end
  end
  
  return nil
end

wire_query = wire_codec(hostname: queried_hostname, type: record_type)
wire64_query = Base64.urlsafe_encode64(wire_query).delete(?=)
connection = prepare_connection(doh_address: doh_address, doh_port: doh_port)
response = doh_get_response(connection, wire64_query: wire64_query)
print_doh_response(response)
