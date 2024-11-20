# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require_relative 'constants'
require_relative 'overloads'

module DNS_to_DoH_proxy
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
end
