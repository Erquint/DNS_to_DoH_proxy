# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require 'net/http'
require 'resolv'
require 'socket'
# require 'G:\Projects\rb\Hyperspector\Hyperspector.rb'

class Resolv::DNS::Name
  alias :to_s_original :to_s
  def to_s(*full)
    vararg_size = full.size()
    vararg_exception = ArgumentError.new('Wrong number of arguments! ' + 
      "(given #{vararg_size}, expected 0..1)")
    type_exception = ArgumentError.new('Only boolean arguments accepted!')
    
    if vararg_size == 0 then
      return(self.to_s_original())
    elsif vararg_size == 1 then
      full = full.first()
      raise(type_exception) unless [TrueClass, FalseClass].include?(full.class())
      return(self.to_s_original()) unless full
      return(self.to_s_original() + (self.absolute?() ? ?. : ''))
    else
      raise(vararg_exception)
    end
  end
end

class Class
  alias :to_s_original :to_s
  def to_s(*short)
    vararg_size = short.size()
    vararg_exception = ArgumentError.new('Wrong number of arguments! ' + 
      "(given #{vararg_size}, expected 0..1)")
    type_exception = ArgumentError.new('Only boolean arguments accepted!')
    
    if vararg_size == 0 then
      return(self.to_s_original())
    elsif vararg_size == 1 then
      short = short.first()
      raise(type_exception) unless [TrueClass, FalseClass].include?(short.class())
      return(self.to_s_original()) unless short
      return(self.to_s().split('::').last())
    else
      raise(vararg_exception)
    end
  end
end
require_relative 'constants'

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
  
  def self.byte_bool?(integer)
    raise('Not an integer!') unless integer.is_a?(Integer)
    return (integer >= 0 && integer <= 1) ? true : false
  end
  
  def self.print_dns_message(dns_message, sender_addrinfo, time)
    if dns_message.is_a?(String) then
      dns_message_decoded = Resolv::DNS::Message.decode(dns_message)
    else
      dns_message_decoded = dns_message
    end
    
    s_class, s_port, s_address_label, s_address = sender_addrinfo
    
    qr = dns_message_decoded.qr() # Unnecessary for a response.
    raise('Invalid QR!') unless byte_bool?(qr)
    qr = qr.zero?() ? 'Query' : 'Response'
    
    id = dns_message_decoded.id()
    
    opcode = dns_message_decoded.opcode()
    raise('Invalid RCODE!') unless OPCODE_ENUM.include?(opcode)
    opcode = OPCODE_ENUM[opcode]
    
    rcode = dns_message_decoded.rcode()
    raise('Invalid RCODE!') unless OPCODE_ENUM.include?(rcode)
    rcode = RCODE_ENUM[rcode]
    
    rd = dns_message_decoded.rd()
    raise('Invalid RD!') unless byte_bool?(rd)
    rd = rd.nonzero?() ? "\e[32mRecurvise question\e[0m" : "\e[33mNon-recursive question\e[0m"
    
    ra = dns_message_decoded.ra()
    raise('Invalid RA!') unless byte_bool?(ra)
    ra = ra.nonzero?() ? "\e[32mRecursive answer\e[0m" : "\e[33mNon-recursive answer\e[0m"
    
    aa = dns_message_decoded.aa()
    raise('Invalid AA!') unless byte_bool?(aa)
    aa = aa.nonzero?() ? "\e[32mAuthoritative answer\e[0m" : "\e[33mNon-authoritative answer\e[0m"
    
    tc = dns_message_decoded.tc()
    raise('Invalid TC!') unless byte_bool?(tc)
    tc = tc.nonzero?() ? "\e[33mTruncated message" : "\e[32mNon-truncated message\e[0m"
    
    questions = dns_message_decoded.question().dup()
    if questions.any?() && questions.all?(){next(_1.size() == 2)} then
      questions.map!() do
        next("#{_1[1].to_s(true)} #{_1[0].to_s(true)}")
      end
      questions = questions.join(?\n)
    else
      questions = 'None.'
    end
    
    authorities = dns_message_decoded.authority().dup()
    if authorities.any?() && authorities.all?(){next(_1.size == 3)} then
      authorities.map!() do
        next(<<~HEREDOC)
          #{_1[0].to_s(true)} #{_1[2].class().to_s(true)}:
            "MNAME:   #{_1[2].mname().to_s()}
            "RNAME:   #{_1[2].rname().to_s()}
            "SERIAL:  #{_1[2].serial().to_s()}
            "REFRESH: #{_1[2].refresh().to_s()}
            "RETRY:   #{_1[2].retry().to_s()}
            "EXPIRE:  #{_1[2].expire().to_s()}
            "MINIMUM: #{_1[2].minimum().to_s()}
            "TTL:     #{_1[1].to_s()}
        HEREDOC
      end
      authorities = authorities.join(?\n)
    else
      authorities = 'None.'
    end
    
    answers = dns_message_decoded.answer().dup()
    if answers.any?() && answers.all?(){next(_1.size == 3)} then
      answers.map!() do
        if _1[2].respond_to?(:address) then
          next("#{_1[2].class().to_s(true)} #{_1[0].to_s(true)} " +
          "#{_1[2].address().class().to_s(true)} " +
          "#{_1[2].address().to_s()} TTL: #{_1[1]}")
        elsif _1[2].respond_to?(:name) then
          next("#{_1[2].class().to_s(true)} #{_1[0].to_s(true)} " +
          "#{_1[2].name().to_s(true)} TTL: #{_1[1]}")
        end
      end
      answers = answers.join(?\n)
    else
      answers = 'None.'
    end
    
    additions = dns_message_decoded.additional().dup()
    additions = 'None.' if additions.empty?()
    
    puts(<<~MESSAGE, nil)
      #{time.strftime((id == 1 ? "\e[34m" : "\e[36m") + "%Y-%m-%d %H:%M:%S\e[0m")}
      Queried by "#{s_address_label}" from #{s_address}:#{s_port} over #{s_class}. #{tc}.
      #{qr} ##{id}: #{opcode} → #{rcode}
      #{rd} → #{ra} (#{aa}).
      \e[35mQuestions:\e[0m
      #{questions}
      \e[35mAuthorities:\e[0m
      #{authorities}
      \e[35mAnswers:\e[0m
      #{answers}
      \e[35mAdditions:\e[0m
      #{additions}
    MESSAGE
    
    return(nil)
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
