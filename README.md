# DNS Facade resolver

Facade DNS Resolver with intercepting functionality
- replaces internal domain to external domain and vice versa
- resolves to upstream resolver
- sets AA flag

## Use Cases
   - Internal domain needs to be MASKED to some external/outside domain, like
       Example: external _cs.company.com_ to internal view _cs.test123.internal)
    - Delegation without DNS forwarder, especially in hybrid environment premises and cloud environments
    - Learn and experiment with DNS
## Architecture
Facade resolver is stateless: without any DB or dynamic zone transfer, file sync. The requests and replies are manipulated on the fly; exchanging external and internal domain names (RR, Auth, Questions section). Only one internal and one external domain are supported in one to one mapping. If you need more domains you need to start more server.
On timeout of the upstream DNS is responses with NXDOMAIN or goes in timeout.

## Disclaimer
This is not production script and without any warranty. Furthermore, DNS packet manipulation is NOT the way.

## Recognition
Based on DNSLib (https://pypi.python.org/pypi/dnslib) examples for interceptor and libraries
## Installation and running
### Install dependencies
One way to install and run can be using __pipenv__ or directly as show down
```python
 pip install dnslib
```
### Run
You need to be root (or use sudo) to bind to port 53
```python
python domain_facade.py	--replace_domain_external myexternal.com --replace_domain_internal myinternal.com -p 53 -u 123.123.123.123:53
```
__Parameters__
```
usage: domain_facade.py [-h] [--port <port>] [--address <address>]
                        [--upstream <dns server:port>] [--tcp]
                        [--timeout <timeout>]
                        [--replace_domain_internal <domain_source>]
                        [--replace_domain_external <domain_destination>]
                        [--log LOG] [--log-prefix]

DNS Facade resolver

optional arguments:
  -h, --help            show this help message and exit
  --port <port>, -p <port>
                        Local proxy port (default:53)
  --address <address>, -a <address>
                        Local proxy listen address (default:all)
  --upstream <dns server:port>, -u <dns server:port>
                        Upstream DNS server:port (default:8.8.8.8:53)
  --tcp                 TCP proxy (default: UDP only)
  --timeout <timeout>, -o <timeout>
                        Upstream timeout (default: 5s)
  --replace_domain_internal <domain_source>
                        internal domain to be replaced
  --replace_domain_external <domain_destination>
                        external target domain
  --log LOG             Log hooks to enable (default:
                        +request,+reply,+truncated,+error,-recv,-send,-data)
  --log-prefix          Log prefix (timestamp/handler/resolver) (default:
                        False)

```

