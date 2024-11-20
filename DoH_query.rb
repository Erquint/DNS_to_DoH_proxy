# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require 'net/http'
require 'resolv'
require 'socket'
# require 'G:\Projects\rb\Hyperspector\Hyperspector.rb'

require_relative 'constants'
require_relative 'overloads'
require_relative 'logging'

module DNS_to_DoH_proxy
  def self.doh_post(connection, dns_message)
    begin
      response = connection.post(Defaults[:path], dns_message, Defaults[:doh_post_headers])
    rescue => exception
      response = exception
    end
    
    return(response)
  end
  
  def self.prepare_doh_connection(doh_address: Defaults[:doh_address], doh_port: Defaults[:doh_port])
    https_connection = Net::HTTP.new(?*, doh_port)
    https_connection.use_ssl = true
    https_connection.ssl_version = :TLSv1_2
    https_connection.verify_hostname = false
    https_connection.ipaddr = doh_address
    
    return(https_connection)
  end
  
  def self.serve_dns_doh_proxy(
      dns_address: Defaults[:dns_address],
      dns_port: Defaults[:dns_port],
      doh_address: Defaults[:doh_address],
      doh_port: Defaults[:doh_port],
      local_address_arpa: Defaults[:local_address_arpa]
    )
    
    begin
      socket = UDPSocket.new()
      socket.bind(dns_address, dns_port)
      puts("DNS server bound to #{dns_address}:#{dns_port}", nil)
      
      while (dns_message, sender_addrinfo = socket.recvfrom(512)).first() do
        time = Time.now()
        handled_locally = false
        sender_class, sender_port, sender_address_label, sender_address = sender_addrinfo
        
        dns_message_decoded = Resolv::DNS::Message.decode(dns_message)
        if dns_message_decoded.question()[0][1] == Resolv::DNS::Resource::IN::PTR &&
          dns_message_decoded.question()[0][0].to_s().include?('1.0.0.127.in-addr.arpa') ||
          dns_message_decoded.question()[0][0].to_s().include?(local_address_arpa) ||
          dns_message_decoded.question()[0][0].to_s().include?('7.3.3.1.in-addr.arpa') ||
          dns_message_decoded.question()[0][0].to_s().include?("1.0.0.0#{'.0'*24}.0.0.0.0.ip6.arpa") ||
          # ↓ Arpa lookup for for mock IPv6 address fe80::100.
          dns_message_decoded.question()[0][0].to_s().include?("0.0.1.0#{'.0'*24}.0.8.e.f.ip6.arpa") ||
          dns_message_decoded.question()[0][0].to_s().include?("7.3.1.1#{'.0'*24}.0.0.0.0.ip6.arpa") then
          
          dns_message_decoded.add_answer(
            dns_message_decoded.question()[0][0], 1,
            Resolv::DNS::Resource::IN::PTR.new(Resolv::DNS::Name.create('erquint.leet.'))
          )
          handled_locally = true
        elsif dns_message_decoded.question()[0][0].to_s() == 'erquint.leet' then
          if dns_message_decoded.question()[0][1] == Resolv::DNS::Resource::IN::A
            dns_message_decoded.add_answer(
              dns_message_decoded.question()[0][0], 1,
              Resolv::DNS::Resource::IN::A.new('1.3.3.7')
            )
          elsif dns_message_decoded.question()[0][1] == Resolv::DNS::Resource::IN::AAAA then
            dns_message_decoded.add_answer(
              dns_message_decoded.question()[0][0], 1,
              Resolv::DNS::Resource::IN::AAAA.new('::1337')
            )
          end
          handled_locally = true
        else
          doh_connection = prepare_doh_connection(doh_address: doh_address, doh_port: doh_port)
          doh_response = doh_post(doh_connection, dns_message)
          raise('TLS connection failed to establish!') if doh_response.is_a?(OpenSSL::SSL::SSLError)
          raise("Failed to query DoH server: #{doh_response.code} #{doh_response.message}!") unless doh_response.code.to_i() == 200
          dns_message = doh_response.body()
        end
        
        if handled_locally then
          print_dns_message(dns_message_decoded, sender_addrinfo, time)
          dns_message = dns_message_decoded.encode()
        else
          print_dns_message(dns_message, sender_addrinfo, time)
        end
        
        socket.send(dns_message, 0, sender_address, sender_port)
      end
      
      raise("Connection closed.\ndns_message: #{dns_message.inspect()}") if dns_message.zero?
      raise("Serving loop broke for unknown reason.\ndns_message: #{dns_message.inspect()}")
    rescue Exception => exception
      if exception.is_a?(Interrupt) then
        puts('Exiting gracefully…')
        exit(0)
      elsif exception.is_a?(Errno::EADDRINUSE) then
        puts(exception)
        exit(1)
      elsif exception.is_a?(Errno::ECONNRESET) then
        puts(<<~HEREDOC)
          #{exception}
          On a UDP-datagram socket this error indicates a previous
          send operation resulted in an ICMP Port Unreachable message.
        HEREDOC
      else
        puts(exception.full_message(highlight: true))
      end
      
      if defined?(socket) && socket && !(socket.closed?()) then
        if defined?(dns_message) && dns_message && dns_message.is_a?(String) then
          dns_message_decoded = Resolv::DNS::Message.decode(dns_message)
          dns_message_decoded.rcode = 2
          dns_message = dns_message_decoded.encode()
          socket.send(dns_message, 0, sender_address, sender_port)
        end
        socket.close()
      end
      
      puts('Re-establishing a socket binding and serving again…')
      
      retry
    end
    
    puts('Rescue loop broke for unknown reason.')
    
    return(nil)
  end
end

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
