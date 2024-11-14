# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require 'net/http'
require 'resolv'
require 'socket'

Defaults = {
  doh_address: '1.1.1.1',
  doh_port: 443,
  dns_address: '0.0.0.0',
  dns_port: 53,
  path: '/dns-query',
  parameter: 'dns'
}

def doh_post_response(connection, wire_message)
  https_post_headers = {
    'Content-Type' => 'application/dns-message',
    'Accept' => 'application/dns-message'
  }
  begin
    response = connection.post(Defaults[:path], wire_message, https_post_headers)
  rescue => exception
    response = exception
  end
  
  return(response)
end

def prepare_doh_connection(doh_address: Defaults[:doh_address], doh_port: Defaults[:doh_port])
  https_connection = Net::HTTP.new(?*, doh_port)
  https_connection.use_ssl = true
  https_connection.ssl_version = :TLSv1_2
  https_connection.verify_hostname = false
  https_connection.ipaddr = doh_address
  
  return(https_connection)
end

def print_doh_response(doh_response_body_decoded)
  if doh_response_body_decoded.answer.any?() then
    puts('Resolved:')
    pp(doh_response_body_decoded.answer)
  else
    puts('Unresolved:')
    pp(doh_response_body_decoded.question)
  end
  
  return(nil)
end

def serve_dns_doh_proxy(
    dns_address: Defaults[:dns_address],
    dns_port: Defaults[:dns_port],
    doh_address: Defaults[:doh_address],
    doh_port: Defaults[:doh_port]
  )
  
  begin
    socket = UDPSocket.new
    socket.bind(dns_address, dns_port)
    
    puts "DNS server started on port #{dns_port}"
    
    while (dns_request, sender_addrinfo = socket.recvfrom(512)).first() do
      sender_class, sender_port, sender_address_label, sender_address = sender_addrinfo
      puts("Queried from \"#{sender_address_label}\" on #{sender_address}:#{sender_port}.")
      doh_connection = prepare_doh_connection(doh_address: doh_address, doh_port: doh_port)
      doh_response = doh_post_response(doh_connection, dns_request)
      raise('TLS connection failed to establish!') if doh_response.is_a?(OpenSSL::SSL::SSLError)
      print_doh_response(Resolv::DNS::Message.decode(doh_response.body))
      socket.send(doh_response.body, 0, sender_address, sender_port)
    end
    
    raise(<<~HEREDOC) if [0, nil].include?(dns_request)
      dns_request: #{dns_request.inspect()}
      When recvfrom(2) returns 0,
      Socket#recv_nonblock returns nil. In most cases it means the connection 
      was closed, but it may also mean an empty packet was received, as the 
      underlying API makes it impossible to distinguish these two cases.
      HEREDOC
    raise('Serving loop broke for unknown reason.')
  rescue => exception
    pp(exception, 'Re-establishing a socket binding and serving again…')
    puts(<<~HEREDOC) if exception.is_a?(Errno::ECONNRESET)
      On a UDP-datagram socket this error indicatesa previous send operation
      resulted in an ICMP Port Unreachable message.
      HEREDOC
    socket.close()
    retry unless exception.is_a?(Interrupt)
  end
  
  return(nil)
end

doh_full_address = ARGV[0]
re_match = doh_full_address.match(/(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?(?!\d)/)
doh_address = re_match[1]
doh_port = (re_match[2] || Defaults[:doh_port]).to_i()
serve_dns_doh_proxy(dns_address: '0.0.0.0', doh_address: doh_address, doh_port: doh_port)
