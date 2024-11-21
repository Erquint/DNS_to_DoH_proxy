# DNS_to_DoH_proxy

This is essentially a Ruby DNS server and DNS/SNI-less DoH client stapled together.  

## Proxy..?

As most name resolution servers are recursive, meaning that they pass queries onward to other known upstream name resolution servers if the query allows it — the term "proxy" applies only vaguely as a distinction.  
And when the query doesn't allow recursion, caching name resolution servers will often still pass it on, without telling the client, in order to enrich their own cache.  

## Purpose.

However, this here server was built with a very specific purpose.  
Let's say I want to connect to a DoH server, which allows encrypting queries with TLS over HTTPS GET and POST requests.  
Unlike many other encrypted evolutions of DNS, DoH is in fact supported natively here and there.  
But there's a catch: HTTPS in the current world of technologies itself relies on SNI for certificate authentication and that in turn relies on name resolution.  
Not only is this a chicken and egg problem, where in order to query a DoH server you must first query a DNS server — weren't we supposed to ditch plaintext DNS servers..?  
But furthermore, it sends the DoH server's domain name in SNI and SNI itself is plaintext.  
It may not be that much of a deal, unless you don't want to be attracting unnecessary attention to both the DoH server you are using, possibly a private one, and the very fact of you using a DoH.  
This may or may not be pertinent to you if you live in an oppressive surveilance state.  
Lastly, not every program is capable of name resolution request over anything other than plain old DNS.  

## Solution.

The mode of this here server's operation is as follows:  
1. Bind to a local DNS (UDP:53) port and listen to client requests.  
2. Once a request arrives, establish a connection with a DoH (HTTPS-POST:443) using an IP address instead of the hostname and pass miniscule garbage as SNI.  
3. Send the request to DoH, receive the response and route it back to the client over UDP.  

There you have it: any random old application capable of querying plain old DNS only shares plaintext locally and not a single unencrupted byte of information leaves your local network.

## Installation.

Just clone the repo or download a ZIP.  
You'll need Ruby to run the code.  

### Windows.

[RubyInstaller for Windows](<https://rubyinstaller.org>)

### Unix.

`sudo apt install ruby`

## Usage.

Make sure that the port `53` is not already taken by another process on your computer.  
This here server will try to stop two largely useless services that Windows runs if you have Hyper-V installed: `SharedAccess` and `hns`. The first prevents the second one from being stopped and the second takes up the port `53`. On Unix, I assume these commands should just fail in the shell harmlessly — don't mind the two errors at the very launch.

Start the server in your terminal by running the following command after navigating to the directory with `cd`:
```
./main.rb 1.2.3.4
```

Replace the IP address `1.2.3.4` in the example with the IP address of the DoH server you want to be querying.  
You can also try specifying a port after a colon.  
You should see `DNS server bound to 0.0.0.0:53` and at this point your server is ready.  
You can point any program at it for name resolution with `127.0.0.1:53` or using the address your local gateway assigned you. Many programs don't accept the port number and just assume it to be 53.  
And don't forget to clear your OS' DNS cache when changing DNS servers:

### Windows.

`ipconfig /flushdns`

### Unix.

Probably…
`sudo /etc/init.d/nscd restart`
OR
`sudo service dns-clean restart`
…depending on distribution.

### Fingerprint feature

Unlike normal name resolution servers, this one here doesn't really keep its own list of records but, for the purposes of confirming that you are in fact connecting to it and that your system's tooling isn't falling back on another server due to misconfiguration, I've included hardcoded records that associate `erquint.leet`, `1.3.3.7` and `::1337` together. Just the first thing that came to mind when ensuring that these values must be invalid when not hardcoded.  
Thus you can test it by running the following command in another terminal:
```
nslookup erquint.leet 127.0.0.1
```
You should see a response similar to this:
```
Server:  erquint.leet
Address:  127.0.0.1

Non-authoritative answer:
Name:    erquint.leet
Addresses:  ::1337
          1.3.3.7
```

## Caveats and consideratons

This project is early in development with many features missing, but seems fast, capable and resilient to be used as is for now.
