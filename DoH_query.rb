# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require 'net/http'
require 'uri'
require 'base64'
require 'resolv'
# require 'G:\Projects\rb\Hyperspector.rb'

module DNS_wire_format
  def self.encode(domain, type)
    message = Resolv::DNS::Message.new()
    message.rd = 1 # Recursion desired
    message.add_question(domain, type)
    return message.encode()
  end
end

def query_DoH(server_url, domain, type = Resolv::DNS::Resource::IN::A)
  query = DNS_wire_format.encode(domain, type)
  encoded_query = Base64.urlsafe_encode64(query).delete('=')

  uri = URI.parse("#{server_url}?dns=#{encoded_query}")
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true if uri.scheme == 'https'

  request = Net::HTTP::Get.new(uri.request_uri)
  request['accept'] = 'application/dns-message'

  response = http.request(request)

  if response.code.to_i == 200
    return response.body
  else
    puts "Failed to query DoH server: #{response.code} #{response.message}"
    return nil
  end
end

server_url = ARGV[0]
domain = ARGV[1]

response = query_DoH(server_url, domain)

if response then
  decoded_response = Resolv::DNS::Message.decode(response)
  puts('Requests:')
  decoded_response.question.each() do |question|
    question.each() do |field|
      puts("  Hostname:\n    #{field}") if field.is_a?(Resolv::DNS::Name)
      puts("  Class:\n    #{field}") if field.is_a?(Class)
    end
  end

  puts('Responses:')
  decoded_response.answer.each() do |answer|
    answer.each() do |field|
      puts("  Address:\n    #{field.address()}") if field.respond_to?(:address)
      puts("  TTL:\n    #{field.ttl()}") if field.respond_to?(:ttl)
    end
  end
end

__END__
