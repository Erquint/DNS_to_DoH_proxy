# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require 'net/http'
require 'resolv'
require 'base64'
# require 'G:\Projects\rb\Hyperspector\Hyperspector.rb'

Defaults = {
  queried_hostname: 'example.com',
  query_type: Resolv::DNS::Resource::IN::A
}

def wire_codec(
    hostname: Defaults[:queried_hostname],
    type: Defaults[:query_type],
    wire64: nil
  )
  if wire64 then
    return Resolv::DNS::Message.decode(wire64)
  else
    message = Resolv::DNS::Message.new()
    message.rd = 1 # Recursion desired
    message.add_question(hostname, type)
    return message.encode()
  end
end

doh_server_address = ARGV[0]
queried_hostname = ARGV[1] || Defaults[:queried_hostname]
record_type = ARGV[2] || ?4

Record_types = {
  ?4 => Resolv::DNS::Resource::IN::A,
  ?6 => Resolv::DNS::Resource::IN::AAAA
}
record_type = Record_types[record_type]

wire_query = wire_codec(hostname: queried_hostname, type: record_type)
wire64_query = Base64.urlsafe_encode64(wire_query).delete(?=)

http = Net::HTTP.new(?*, 443)
http.use_ssl = true
http.ssl_version = :TLSv1_2
http.verify_hostname = false
http.ipaddr = doh_server_address
http_get_options = {'accept' => 'application/dns-message'}
response = http.get('/dns-query?dns=' + wire64_query, http_get_options)

if response.code.to_i == 200
  response = wire_codec(wire64: response.body)
else
  raise("Failed to query DoH server: #{response.code} #{response.message}")
end

if response then
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
end
