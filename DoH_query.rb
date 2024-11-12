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

# Get command-line arguments
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
# def native_inspect(object)
#   return Object.instance_method(:inspect).bind(object).call()
# end

# def p(*input)
#   return puts(*(input.map(){native_inspect(_1)}))
# end


  # puts(decoded_response.question.map(){|question| question.map(){|field| next "  #{field}"}}, ?\n)

  # puts(decoded_response.question.map(){|question| question.map(){|field| "  #{field}" }.join("\n") })
  # Rewrite the above to indent output with 2 spaces


  # puts(decoded_response.answer.map(){|answer| answer.each(){|field| next field}}, ?\n)
  # puts('Giblets:')
 
  # puts decoded_response.answer().first().last().address().to_s()
  
  # puts "Response from DoH server:"
  # puts response.inspect
  
  # Print the decoded response
  # puts "Decoded response:"
  # puts decoded_response
  
  # puts 'Each:'
  # puts 'Question:'
  # p decoded_response.each_question(){}
  # puts 'Resource:'
  # decoded_response.each_resource(){p _1.inspect}
  
  # puts 'Question:'
  # p decoded_response.question
  # puts 'Answer:'
  # p decoded_response.answer.first[2].class
  # p decoded_response.answer.first[2].class.instance_method(:inspect).source_location
  # p decoded_response.answer.first[2].class.instance_method(:inspect).source
  # puts decoded_response.answer.class.instance_method(:inspect).source_location
  # puts 'Authority:'
  # p decoded_response.authority
  # puts 'Additional:'
  # p decoded_response.additional
  # puts decoded_response.address
  
  # Extract the IP address from the DNS response
  
  # Print the IP address

puts(decoded_response.question.map(){|question| question.each(){|field| next "#{field}"}}, ?\n)
# Rewrite the above to indent output with 2 spaces
puts(decoded_response.question.map(){|question| question.each(){|field| next "  #{field}"}}, ?\n)
# But that doesn't work. Why?


# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require 'net/http'
require 'uri'
require 'base64'
require 'resolv'

module DNS_wire_format
  def self.encode(domain, type)
  message = Resolv::DNS::Message.new()
  message.rd = 1 # Recursion desired
  message.add_question(domain, type)
  return message.encode()
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

# Get command-line arguments
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
# def native_inspect(object)
#   return Object.instance_method(:inspect).bind(object).call()
# end

# def p(*input)
#   return puts(*(input.map(){native_inspect(_1)}))
# end


  # puts(decoded_response.question.map(){|question| question.map(){|field| next "  #{field}"}}, ?\n)

  # puts(decoded_response.question.map(){|question| question.map(){|field| "  #{field}" }.join("\n") })
  # Rewrite the above to indent output with 2 spaces


  # puts(decoded_response.answer.map(){|answer| answer.each(){|field| next field}}, ?\n)
  # puts('Giblets:')
 
  # puts decoded_response.answer().first().last().address().to_s()
  
  # puts "Response from DoH server:"
  # puts response.inspect
  
  # Print the decoded response
  # puts "Decoded response:"
  # puts decoded_response
  
  # puts 'Each:'
  # puts 'Question:'
  # p decoded_response.each_question(){}
  # puts 'Resource:'
  # decoded_response.each_resource(){p _1.inspect}
  
  # puts 'Question:'
  # p decoded_response.question
  # puts 'Answer:'
  # p decoded_response.answer.first[2].class
  # p decoded_response.answer.first[2].class.instance_method(:inspect).source_location
  # p decoded_response.answer.first[2].class.instance_method(:inspect).source
  # puts decoded_response.answer.class.instance_method(:inspect).source_location
  # puts 'Authority:'
  # p decoded_response.authority
  # puts 'Additional:'
  # p decoded_response.additional
  # puts decoded_response.address
  
  # Extract the IP address from the DNS response
  
  # Print the IP address



# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require 'net/http'
require 'uri'
require 'base64'
require 'resolv'

def dns_query_to_wire_format(domain, type)
  message = Resolv::DNS::Message.new
  message.rd = 1 # Recursion desired
  message.add_question(domain, type)
  message.encode
end

def query_doh(server_url, domain, type = Resolv::DNS::Resource::IN::A)
  query = dns_query_to_wire_format(domain, type)
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

# Example usage
server_url = 'https://cloudflare-dns.com/dns-query'
domain = 'example.com'

response = query_doh(server_url, domain)

if response
  puts "Response from DoH server:"
  puts response.inspect

  # Decode the response
  decoded_response = Resolv::DNS::Message.decode(response)

  # Print the decoded response
  puts "Decoded response:"
  puts decoded_response
  
  puts 'Each:'
  puts 'Question:'
  p decoded_response.each_question(){}
  puts 'Resource:'
  decoded_response.each_resource(){p _1.inspect}
  
  puts 'Question:'
  p decoded_response.question
  puts 'Answer:'
  p decoded_response.answer
  puts 'Authority:'
  p decoded_response.authority
  puts 'Additional:'
  p decoded_response.additional
  # puts decoded_response.address

  # Extract the IP address from the DNS response
  ip_address = decoded_response.answer.first.last.address.to_s

  # Print the IP address
  puts "IP address:"
  puts ip_address
end




# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require 'resolv'

pesky_object = Marshal.load("\x04\b[\x06[\bo:\x16Resolv::DNS::Name\a:\f@labels[\ao:\x1CResolv::DNS::Label::Str\a:\f@string\"\fexample:\x0E@downcase\"\fexampleo;\a\a;\b\"\bcom;\t\"\bcom:\x0E@absoluteTi\x02N\no:!Resolv::DNS::Resource::IN::A\a:\r@addresso:\x11Resolv::IPv4\x06;\f\"\t]\xB8\xD7\x0E:\t@ttli\x02N\n")

puts("pesky_object <#{pesky_object.class}>")
print("  p:\n    ", pesky_object.inspect, ?\n)
print("  p Object#inspect:\n    ", Object.instance_method(:inspect).bind(pesky_object).call(), ?\n)
print("  p Array#inspect:\n    ", Array.instance_method(:inspect).bind(pesky_object).call(), ?\n)
sub_pesky_object = pesky_object.first.first
print("  p Object#instance_variables:\n    ", sub_pesky_object.instance_variables.inspect, ?\n)
puts(nil, "sub_pesky_object <#{sub_pesky_object.class}>:")
print("  p ivar(:@labels):\n    ", sub_pesky_object.instance_variable_get(:@labels).inspect, ?\n)
print("  p ivar(:@absolute):\n    ", sub_pesky_object.instance_variable_get(:@absolute).inspect, ?\n)
print("  p Resolv::DNS::Name#inspect:\n    ", sub_pesky_object.inspect, ?\n)
print("  p Resolv::DNS::Name#to_s:\n    ", sub_pesky_object.to_s, ?\n)

__END__
pesky_object <Array>
  p:
    [[#<Resolv::DNS::Name: example.com.>, 2638, #<Resolv::DNS::Resource::IN::A:0x000001ecdbab1160 @address=#<Resolv::IPv4 93.184.215.14>, @ttl=2638>]]
  p Object#inspect:
    #<Array:0x000001ecdbab14d0>
  p Array#inspect:
    [[#<Resolv::DNS::Name: example.com.>, 2638, #<Resolv::DNS::Resource::IN::A:0x000001ecdbab1160 @address=#<Resolv::IPv4 93.184.215.14>, @ttl=2638>]]
  p Object#instance_variables:
    [:@labels, :@absolute]

sub_pesky_object <Resolv::DNS::Name>:
  p ivar(:@labels):
    [#<Resolv::DNS::Label::Str example>, #<Resolv::DNS::Label::Str com>]
  p ivar(:@absolute):
    true
  p Resolv::DNS::Name#inspect:
    #<Resolv::DNS::Name: example.com.>
  p Resolv::DNS::Name#to_s:
    example.com




# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require 'resolv'
pesky = Marshal.load("\x04\b[\x06[\bo:\x16Resolv::DNS::Name\a:\f@labels[\ao:\x1CResolv::DNS::Label::Str\a:\f@string\"\fexample:\x0E@downcase\"\fexampleo;\a\a;\b\"\bcom;\t\"\bcom:\x0E@absoluteTi\x02N\no:!Resolv::DNS::Resource::IN::A\a:\r@addresso:\x11Resolv::IPv4\x06;\f\"\t]\xB8\xD7\x0E:\t@ttli\x02N\n")


module Hyperspection
  def self.inspect(object, top = true, recurse = true)
    # throw(:top_return) if top && !(object.is_a?(Array))
    if(recurse) then
      if object.is_a?(Array) then
        object.each(){self.inspect(_1, false)}
      elsif object.instance_variables.any?() then
        self.inspect(object, false, false)
        object.instance_variables.each() do
          self.inspect(object.instance_variable_get(_1), false)
        end
      end
    else
      object.define_singleton_method(:inspect) do
        Object.instance_method(:inspect).bind(_1).call()
      end
      return nil
    end
    # catch(:top_return)
    return object.inspect() if top
  end
end

p Hyperspection.inspect(pesky)

__END__
pesky_object <Array>
  p:
    [[#<Resolv::DNS::Name: example.com.>, 2638, #<Resolv::DNS::Resource::IN::A:0x000001ecdbab1160 @address=#<Resolv::IPv4 93.184.215.14>, @ttl=2638>]]
  p Object#inspect:
    #<Array:0x000001ecdbab14d0>
  p Array#inspect:
    [[#<Resolv::DNS::Name: example.com.>, 2638, #<Resolv::DNS::Resource::IN::A:0x000001ecdbab1160 @address=#<Resolv::IPv4 93.184.215.14>, @ttl=2638>]]
  p Object#instance_variables:
    [:@labels, :@absolute]

sub_pesky_object <Resolv::DNS::Name>:
  p ivar(:@labels):
    [#<Resolv::DNS::Label::Str example>, #<Resolv::DNS::Label::Str com>]
  p ivar(:@absolute):
    true
  p Resolv::DNS::Name#inspect:
    #<Resolv::DNS::Name: example.com.>
  p Resolv::DNS::Name#to_s:
    example.com

# instance_variables.map { |ivar| [ivar, instance_variable_get(ivar)] }.to_h
