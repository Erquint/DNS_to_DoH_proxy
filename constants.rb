# encoding: ASCII-8BIT
Encoding.default_external = Encoding::ASCII_8BIT
Encoding.default_internal = Encoding::ASCII_8BIT

module DNS_to_DoH_proxy
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
end
