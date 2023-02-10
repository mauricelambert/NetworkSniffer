![NetworkSniffer logo](https://mauricelambert.github.io/info/python/security/NetworkSniffer_small.png "NetworkSniffer logo")

# NetworkSniffer

## Description

This module sniffs network communications without any requirements (without scapy/npcap/winpcap).

## Requirements

This package require:
 - python3
 - python3 Standard Library

## Installation

```bash
pip install NetworkSniffer
```

## Usages

### Command line

```bash
python3 -m NetworkSniffer
python3 NetworkSniffer.pyz -x -s -c
NetworkSniffer -x -X -c
NetworkSniffer -x -s -t -c
NetworkSniffer -x -s -u -c
NetworkSniffer -x -s -4 -c
NetworkSniffer -x -s -6 -c
NetworkSniffer -x -s -c -n '192.168.56.0/24'
NetworkSniffer -x -s -c -n '10.0.0.0/8' '192.168.56.0/24'
NetworkSniffer -x -s -c -p 80
NetworkSniffer -x -s -c -p 80 53
NetworkSniffer -x -s -c -m '00:00:00:00:00:00'
NetworkSniffer -x -s -c -m '00:00:00:00:00:00' '08:00:27:b1:9d:67'
NetworkSniffer -x -s -c -i '192.168.56.101'
NetworkSniffer -x -s -c -i '192.168.56.101' '10.0.2.15'
NetworkSniffer -c -l 20
NetworkSniffer -x -s -f 'test.txt'
```

### Python script

```python
from NetworkSniffer import *

sniffer = Sniffer(
    [('192.168.0.47', 0), ('192.168.56.1', 0)],
    [('fe80:0000:0000:0000:6cc8:2732:3de4:496b', 0, 0, 18)],
    (summary, hexadecimal),
)
sniffer.sniff() 

SnifferFilters = new_class(
    "SnifferFilters",
    (TcpFilter, Sniffer),
    {},
)
sniffer = SnifferFilters(
    [('192.168.0.47', 0), ('192.168.56.1', 0)],
    [('fe80:0000:0000:0000:6cc8:2732:3de4:496b', 0, 0, 18)],
    (summary, hexadecimal),
    tcp_filter=True,
)
sniffer.sniff() 

ipv4_addresses, ipv6_addresses = get_addresses()
sniffer = Sniffer(
    ipv4_addresses,
    ipv6_addresses,
    (raw,),
)
sniffer.sniff() 
```

## Links

 - [Github Page](https://github.com/mauricelambert/NetworkSniffer/)
 - [Documentation](https://mauricelambert.github.io/info/python/security/NetworkSniffer.html)
 - [Pypi package](https://pypi.org/project/NetworkSniffer/)
 - [Executable](https://mauricelambert.github.io/info/python/security/NetworkSniffer.pyz)

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
