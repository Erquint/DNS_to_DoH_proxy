# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

require_relative 'constants'

module DNS_to_DoH_proxy
  def self.prepare_doh_connection(doh_address: Defaults[:doh_address], doh_port: Defaults[:doh_port])
    https_connection = Net::HTTP.new(?*, doh_port)
    https_connection.use_ssl = true
    https_connection.ssl_version = :TLSv1_2
    https_connection.verify_hostname = false
    https_connection.ipaddr = doh_address
    
    return(https_connection)
  end
  
  def self.doh_post(connection, dns_message)
    begin
      response = connection.post(Defaults[:path], dns_message, Defaults[:doh_post_headers])
    rescue => exception
      response = exception
    end
    
    return(response)
  end
end
