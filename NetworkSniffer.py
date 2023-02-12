#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This module sniffs network communications without any requirements
#    Copyright (C) 2023  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
##################

"""
This module sniffs network communications without any requirements

~# python3.11 NetworkSniffer.py -c
0000  00 00 00 45 56 ab 00 00 00 ba 65 54 08 00 45 00  RT..5...'..g..E.
0010  00 54 42 e4 40 00 40 01 db a6 0a 00 02 0f 08 08  .TB.@.@.........
0020  08 08 08 00 71 3c 5a 9c 00 01 1f 63 e5 63 00 00  ....q<Z....c.c..
0030  00 00 68 8c 00 00 00 00 00 00 10 11 12 13 14 15  ..h.............
0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25  .......... !"#$%
0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35  &'()*+,-./012345
0060  36 37                                            67
~# python3.11 NetworkSniffer.py -x -s -c
[Internet Protocol version 4 (IPv4) ICMP][64] 10.0.2.15(00:00:00:ba:65:54):0 -> 8.8.8.8(00:00:00:45:56:ab):0
~# python3.11 NetworkSniffer.py -x -X -c
0000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1..
0010  48 6f 73 74 3a 20 65 78 61 6d 70 6c 65 2e 63 6f  Host: example.co                                                                                                         
0020  6d 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 63  m..User-Agent: c                                                                                                         
0030  75 72 6c 2f 37 2e 38 37 2e 30 0d 0a 41 63 63 65  url/7.87.0..Acce                                                                                                         
0040  70 74 3a 20 2a 2f 2a 0d 0a 0d 0a                 pt: */*....
~# python3.11 NetworkSniffer.py -x -r -c
<raw data>
GET / HTTP/1.1
Host: example.com
User-Agent: python/5.72
Accept: */*
<raw data>
~# python3.11 NetworkSniffer.py -x -R -c
GET / HTTP/1.1
Host: example.com
User-Agent: Python5.72
Accept: */*

HTTP/1.1 200 OK
Age: 278171
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Thu, 22 Jun 2016 07:18:26 GMT
Etag: "3147526947+ident"
Expires: Thu, 22 Jun 2016 07:18:26 GMT
Last-Modified: Thu, 22 Jun 2016 07:18:26 GMT
Server: ECS (dcb/7F83)
Vary: Accept-Encoding
X-Cache: HIT
Content-Length: 1256

<HTTP body content>
~# python3.11 NetworkSniffer.py -x -s -t -c
[Internet Protocol version 4 (IPv4) TCP Flags: S][0] 10.0.2.15(00:00:00:ba:65:54):38974 -> 93.184.216.34(00:00:00:45:56:ab):80
~# python3.11 NetworkSniffer.py -x -s -u -c
[Internet Protocol version 4 (IPv4) UDP][282] 192.168.56.101(08:00:27:c5:14:72):68 -> 192.168.56.100(08:00:27:e6:dc:08):67
~# python3.11 NetworkSniffer.py -x -s -4 -c
[Internet Protocol version 4 (IPv4) ICMP][64] 10.0.2.15(00:00:00:ba:65:54):0 -> 8.8.8.8(00:00:00:45:56:ab):0
~# python3.11 NetworkSniffer.py -x -s -6 -c
[Internet Protocol Version 6 (IPv6) IPv6-ICMP][64] fe80:0000:0000:0000:2541:637:8596:fedc(00:00:00:00:00:00):0 -> fe80:0000:0000:0000:2541:637:8596:fedc(00:00:00:00:00:00):0
~# python3.11 NetworkSniffer.py -x -s -c -n '192.168.56.0/24'
[Internet Protocol version 4 (IPv4) TCP Flags: S][0] 192.168.56.1(0a:00:27:00:00:0f):65385 -> 192.168.56.101(08:00:27:c5:14:72):8000
~# python3.11 NetworkSniffer.py -x -s -c -n '10.0.0.0/8' '192.168.56.0/24'
[Internet Protocol version 4 (IPv4) ICMP][64] 10.0.2.15(00:00:00:ba:65:54):0 -> 8.8.8.8(00:00:00:45:56:ab):0
~# python3.11 NetworkSniffer.py -x -s -c -p 80 53
[Internet Protocol version 4 (IPv4) UDP Flags: F][36] 10.0.2.15(00:00:00:ba:65:54):53678 -> 172.16.0.1(00:00:00:45:56:ab):53
~# python3.11 NetworkSniffer.py -x -s -c -m '00:00:00:00:00:00'
[Internet Protocol Version 6 (IPv6) IPv6-ICMP][64] fe80:0000:0000:0000:2541:637:8596:fedc(00:00:00:00:00:00):0 -> fe80:0000:0000:0000:2541:637:8596:fedc(00:00:00:00:00:00):0
~# python3.11 NetworkSniffer.py -x -s -c -m '00:00:00:00:00:00' '00:00:00:ba:65:54'
[Internet Protocol version 4 (IPv4) ICMP][64] 10.0.2.15(00:00:00:ba:65:54):0 -> 8.8.8.8(00:00:00:45:56:ab):0
~# python3.11 NetworkSniffer.py -x -s -c -i '192.168.56.101'
[Internet Protocol version 4 (IPv4) UDP][282] 192.168.56.101(08:00:27:c5:14:72):68 -> 192.168.56.100(08:00:27:e6:dc:08):67
~# python3.11 NetworkSniffer.py -x -s -c -i '192.168.56.101' '10.0.2.15'
[Internet Protocol version 4 (IPv4) ICMP][64] 10.0.2.15(00:00:00:ba:65:54):0 -> 8.8.8.8(00:00:00:45:56:ab):0
~# python3.11 NetworkSniffer.py -c -l 20
0000  00 00 00 45 56 ab 00 00 00 ba 65 54 08 00 45 00 00 54 9f 1a  RT..5...'..g..E..T..
0014  40 00 40 01 7f 70 0a 00 02 0f 08 08 08 08 08 00 f3 11 ff 34  @.@..p.............4                                                                                         
0028  00 01 5a 65 e5 63 00 00 00 00 03 1c 04 00 00 00 00 00 10 11  ..Ze.c..............                                                                                         
003c  12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25  .............. !"#$%                                                                                         
0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37        &'()*+,-./01234567
~# python3.11 NetworkSniffer.py -x -s -f 'test.txt'
~#

>>> sniffer = Sniffer(
...     [('172.17.0.1', 0), ('192.168.56.1', 0)],
...     [('fe80:0000:0000:0000:1425:3647:5869:abcd', 0, 0, 18)],
...     (summary, hexadecimal),
... )
>>> sniffer.sniff()
<sniffed data>
>>> 

>>> SnifferFilters = new_class(
...     "SnifferFilters",
...     (TcpFilter, Sniffer),
...     {},
... )
>>> sniffer = SnifferFilters(
...     [('172.17.0.1', 0), ('192.168.56.1', 0)],
...     [('fe80:0000:0000:0000:1425:3647:5869:abcd', 0, 0, 18)],
...     (summary, hexadecimal),
...     tcp_filter=True,
... )
>>> sniffer.sniff()
<sniffed data>
>>> 

>>> ipv4_addresses, ipv6_addresses = get_addresses()
>>> sniffer = Sniffer(
...     ipv4_addresses,
...     ipv6_addresses,
...     (raw,),
... )
>>> sniffer.sniff()
<sniffed data>
>>> 
"""

__version__ = "0.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = (
    "This module sniffs network communications without any requirements"
)
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/NetworkSniffer"

copyright = """
NetworkSniffer  Copyright (C) 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = [
    "Sniffer",
    "MacFilter",
    "IpFilter",
    "PortsFilter",
    "TcpFilter",
    "UdpFilter",
    "IPv4Filter",
    "IPv6Filter",
    "NetworksFilter",
    "hexadecimal",
    "hexadecimal_data",
    "raw",
    "raw_data",
    "summary",
    "get_addresses",
]

print(copyright)

from socket import (
    gethostname,
    getaddrinfo,
    socket,
    ntohs,
    AF_INET,
    AF_INET6,
    SOCK_RAW,
    IPPROTO_IP,
)
from ipaddress import (
    ip_network,
    ip_address,
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
)
from typing import (
    Tuple,
    Dict,
    List,
    Any,
    Union,
    Iterable,
    TypeVar,
    Optional,
    Type,
)
from argparse import ArgumentParser, Namespace, FileType
from sys import exit, platform, stdout
from collections.abc import Callable
from collections import namedtuple
from contextlib import suppress
from types import TracebackType
from functools import partial
from binascii import hexlify
from threading import Thread
from string import printable
from types import new_class
from struct import unpack
from warnings import warn
from _io import _IOBase

is_windows: bool = platform == "win32"

if is_windows:
    from socket import (
        IP_HDRINCL,
        SIO_RCVALL,
        RCVALL_ON,
        RCVALL_OFF,
        IPPROTO_IPV6,
        IPV6_PKTINFO,
    )
else:
    from socket import AF_PACKET

WindowsRawSocket = TypeVar("WindowsRawSocket")

Ethernet: type = namedtuple(
    "Ethernet", ["destination", "source", "type", "data"]
)

IPv4: type = namedtuple(
    "IPv4",
    [
        "version",
        "header_length",
        "services",
        "data_length",
        "identification",
        "flags",
        "fragment_offset",
        "time_to_live",
        "protocol",
        "checksum",
        "source",
        "destination",
        "data",
    ],
)
IpFlags: type = namedtuple("IpFlags", ["value", "reserved", "df", "mf"])

TrafficClass: type = namedtuple(
    "TrafficClass",
    ["value", "services_codepoint", "explicit_congestion_notification"],
)
IPv6: type = namedtuple(
    "IPv6",
    [
        "version",
        "traffic_class",
        "flow_label",
        "data_length",
        "protocol",
        "hop_limit",
        "source",
        "destination",
        "data",
    ],
)

TCP: type = namedtuple(
    "TCP",
    [
        "source",
        "destination",
        "sequence_number",
        "acknowledgment_number",
        "header_length",
        "flags",
        "window",
        "checksum",
        "urgent_pointer",
        "data",
    ],
)
TcpFlags: type = namedtuple(
    "TcpFlags",
    [
        "value",
        "accurate_ecn",
        "congestion_window_reduced",
        "ecn_echo",
        "urgent",
        "acknowledgment",
        "push",
        "reset",
        "syn",
        "fin",
    ],
)

UDP: type = namedtuple(
    "UDP", ["source", "destination", "length", "checksum", "data"]
)

Unknow: type = namedtuple(
    "Unknow", ["type", "protocol", "source", "destination", "data"]
)

raw_output: _IOBase = stdout.buffer
printable: bytes = printable[:-5].encode("ascii")

ethernet_types: Dict[int, str] = {
    0x0800: "Internet Protocol version 4 (IPv4)",
    0x0806: "Address Resolution Protocol (ARP)",
    0x0842: "Wake-on-LAN",
    0x22EA: "Stream Reservation Protocol",
    0x22F0: "Audio Video Transport Protocol (AVTP)",
    0x22F3: "IETF TRILL Protocol",
    0x6002: "DEC RC",
    0x6003: "DECnet Phase IV, DNA Routing",
    0x6004: "DEC",
    0x8035: "Reverse Address Resolution Protocol (RARP)",
    0x809B: "AppleTalk (Ethertalk)",
    0x80F3: "AppleTalk Address Resolution Protocol (AARP)",
    0x8100: (
        "VLAN-tagged frame (IEEE 802.1Q) and Shortest"
        " Path Bridging IEEE 802.1aq with NNI compatibility"
    ),
    0x8102: "Simple Loop Prevention Protocol (SLPP)",
    0x8103: "Virtual Link Aggregation Control Protocol (VLACP)",
    0x8137: "IPX",
    0x8204: "QNX Qnet",
    0x86DD: "Internet Protocol Version 6 (IPv6)",
    0x8808: "Ethernet flow control",
    0x8809: (
        "Ethernet Slow Protocols such as the Link"
        " Aggregation Control Protocol (LACP)"
    ),
    0x8819: "CobraNet",
    0x8847: "MPLS unicast",
    0x8848: "MPLS multicast",
    0x8863: "PPPoE Discovery Stage",
    0x8864: "PPPoE Session Stage",
    0x887B: "HomePlug 1.0 MME",
    0x888E: "EAP over LAN (IEEE 802.1X)",
    0x8892: "PROFINET Protocol",
    0x889A: "HyperSCSI (SCSI over Ethernet)",
    0x88A2: "ATA over Ethernet",
    0x88A4: "EtherCAT Protocol",
    0x88A8: "Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel .",
    0x88AB: "Ethernet Powerlink",
    0x88B8: "GOOSE (Generic Object Oriented Substation event)",
    0x88B9: "GSE (Generic Substation Events) Management Services",
    0x88BA: "SV (Sampled Value Transmission)",
    0x88BF: "MikroTik RoMON (unofficial)",
    0x88CC: "Link Layer Discovery Protocol (LLDP)",
    0x88CD: "SERCOS III",
    0x88E1: "HomePlug Green PHY",
    0x88E3: "Media Redundancy Protocol (IEC62439-2)",
    0x88E5: "IEEE 802.1AE MAC security (MACsec)",
    0x88E7: "Provider Backbone Bridges (PBB) (IEEE 802.1ah)",
    0x88F7: "Precision Time Protocol (PTP) over IEEE 802.3 Ethernet",
    0x88F8: "NC-SI",
    0x88FB: "Parallel Redundancy Protocol (PRP)",
    0x8902: "IEEE 802.1ag )",
    0x8906: "Fibre Channel over Ethernet (FCoE)",
    0x8914: "FCoE Initialization Protocol",
    0x8915: "RDMA over Converged Ethernet (RoCE)",
    0x891D: "TTEthernet Protocol Control Frame (TTE)",
    0x892F: "High-availability Seamless Redundancy (HSR)",
    0x893A: "1905.1 IEEE Protocol",
    0x9000: "Ethernet Configuration Testing Protocol",
    0xF1C1: (
        "Redundancy Tag (IEEE 802.1CB Frame Replication"
        " and Elimination for Reliability)"
    ),
}

ethernet_types_functions: Dict[int, str] = {
    0x0800: "ipv4_parse",
    0x86DD: "ipv6_parse",
}

ip_protocols: Dict[int, str] = {
    0x00: "HOPOPT",
    0x01: "ICMP",
    0x02: "IGMP",
    0x03: "GGP",
    0x04: "IP-in-IP",
    0x05: "ST",
    0x06: "TCP",
    0x07: "CBT",
    0x08: "EGP",
    0x09: "IGP",
    0x0A: "BBN-RCC-MON",
    0x0B: "NVP-II",
    0x0C: "PUP",
    0x0D: "ARGUS",
    0x0E: "EMCON",
    0x0F: "XNET",
    0x10: "CHAOS",
    0x11: "UDP",
    0x12: "MUX",
    0x13: "DCN-MEAS",
    0x14: "HMP",
    0x15: "PRM",
    0x16: "XNS-IDP",
    0x17: "TRUNK-1",
    0x18: "TRUNK-2",
    0x19: "LEAF-1",
    0x1A: "LEAF-2",
    0x1B: "RDP",
    0x1C: "IRTP",
    0x1D: "ISO-TP4",
    0x1E: "NETBLT",
    0x1F: "MFE-NSP",
    0x20: "MERIT-INP",
    0x21: "DCCP",
    0x22: "3PC",
    0x23: "IDPR",
    0x24: "XTP",
    0x25: "DDP",
    0x26: "IDPR-CMTP",
    0x27: "TP++",
    0x28: "IL",
    0x29: "IPv6",
    0x2A: "SDRP",
    0x2B: "IPv6-Route",
    0x2C: "IPv6-Frag",
    0x2D: "IDRP",
    0x2E: "RSVP",
    0x2F: "GRE",
    0x30: "DSR",
    0x31: "BNA",
    0x32: "ESP",
    0x33: "AH",
    0x34: "I-NLSP",
    0x35: "SwIPe",
    0x36: "NARP",
    0x37: "MOBILE",
    0x38: "TLSP",
    0x39: "SKIP",
    0x3A: "IPv6-ICMP",
    0x3B: "IPv6-NoNxt",
    0x3C: "IPv6-Opts",
    0x3D: "Any host internal protocol",
    0x3E: "CFTP",
    0x3F: "Any local network",
    0x40: "SAT-EXPAK",
    0x41: "KRYPTOLAN",
    0x42: "RVD",
    0x43: "IPPC",
    0x44: "Any distributed file system",
    0x45: "SAT-MON",
    0x46: "VISA",
    0x47: "IPCU",
    0x48: "CPNX",
    0x49: "CPH",
    0x4A: "WSN",
    0x4B: "PVP",
    0x4C: "BR-SAT-MON",
    0x4D: "SUN-ND",
    0x4E: "WB-MON",
    0x4F: "WB-EXPAK",
    0x50: "ISO-IP",
    0x51: "VMTP",
    0x52: "SECURE-VMTP",
    0x53: "VINES",
    0x54: "IPTM",
    0x55: "NSFNET-IGP",
    0x56: "DGP",
    0x57: "TCF",
    0x58: "EIGRP",
    0x59: "OSPF",
    0x5A: "Sprite-RPC",
    0x5B: "LARP",
    0x5C: "MTP",
    0x5D: "AX.25",
    0x5E: "OS",
    0x5F: "MICP",
    0x60: "SCC-SP",
    0x61: "ETHERIP",
    0x62: "ENCAP",
    0x63: "Any private encryption scheme",
    0x64: "GMTP",
    0x65: "IFMP",
    0x66: "PNNI",
    0x67: "PIM",
    0x68: "ARIS",
    0x69: "SCPS",
    0x6A: "QNX",
    0x6B: "A/N",
    0x6C: "IPComp",
    0x6D: "SNP",
    0x6E: "Compaq-Peer",
    0x6F: "IPX-in-IP",
    0x70: "VRRP",
    0x71: "PGM",
    0x72: "Any 0-hop protocol",
    0x73: "L2TP",
    0x74: "DDX",
    0x75: "IATP",
    0x76: "STP",
    0x77: "SRP",
    0x78: "UTI",
    0x79: "SMP",
    0x7A: "SM",
    0x7B: "PTP",
    0x7C: "IS-IS over IPv4",
    0x7D: "FIRE",
    0x7E: "CRTP",
    0x7F: "CRUDP",
    0x80: "SSCOPMCE",
    0x81: "IPLT",
    0x82: "SPS",
    0x83: "PIPE",
    0x84: "SCTP",
    0x85: "FC",
    0x86: "RSVP-E2E-IGNORE",
    0x87: "Mobility Header",
    0x88: "UDPLite",
    0x89: "MPLS-in-IP",
    0x8A: "manet",
    0x8B: "HIP",
    0x8C: "Shim6",
    0x8D: "WESP",
    0x8E: "ROHC",
    0x8F: "Ethernet",
    0xFF: "Reserved",
}

ip_protocols.update({x: "Unassigned" for x in range(0x90, 0xFC)})
ip_protocols.update(
    {x: "Experimentation & Testing" for x in range(0xFD, 0xFE)}
)

ip_protocols_functions: Dict[int, str] = {
    0x06: "tcp_parse",
    0x11: "udp_parse",
}

file: _IOBase = stdout
format_size: int = 47
line_size: int = 16


class Sniffer:

    """
    This class implements a multi-platform sniffer
    without any external package.
    """

    def __init__(
        self,
        ipv4s: List[Tuple[str, int]],
        ipv6s: List[Tuple[str, int, int, int]],
        callbacks: Iterable[Callable],
    ):
        self.ipv4s = ipv4s
        self.ipv6s = ipv6s

        self.callbacks = callbacks

    def windows_sniff(self) -> None:
        """
        This method starts the raw socket on Windows
        platform and sniffs IP packets.
        """

        def sniff(socket: WindowsRawSocket) -> None:
            recvfrom: Callable = socket.socket.recvfrom
            do_receive: Callable = socket.do_receive
            while True:
                try:
                    packet = recvfrom(65565)
                except OSError:
                    break
                Thread(target=do_receive, args=packet).start()

        if self.ipv4s:
            main_ip = self.ipv4s[0]
            ipv4s = self.ipv4s[1:]
            ipv6s = self.ipv6s
            version = 4
        elif self.ipv6s:
            main_ip = (self.ipv6s[0], 6)
            ipv4s = self.ipv4s
            ipv6s = self.ipv6s[1:]
            version = 6
        else:
            raise RuntimeError("There are no ip address to sniff.")

        sockets = []
        add = sockets.append
        with suppress(KeyboardInterrupt):
            for ip in ipv6s:
                socketv6 = WindowsRawSocket(self, ip, 6)
                socketv6 = socketv6.__enter__()
                add(socketv6)
                Thread(target=sniff, args=(socketv6,)).start()
            for ip in ipv4s:
                socketv4 = WindowsRawSocket(self, ip, 4)
                socketv4 = socketv4.__enter__()
                add(socketv4)
                Thread(target=sniff, args=(socketv4,)).start()

            with WindowsRawSocket(self, main_ip, version) as main_socket:
                sniff(main_socket)

        for socket_ in sockets:
            socket_.__exit__()

    def linux_sniff(self) -> None:
        """
        This method starts the raw socket and sniffs ethernet frames.
        """

        socket_ = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))

        with suppress(KeyboardInterrupt):
            while True:
                Thread(
                    target=self.linux_do_receive, args=socket_.recvfrom(65565)
                ).start()

        socket_.close()

    if is_windows:
        sniff = windows_sniff
    else:
        sniff = linux_sniff

    def windows_do_receive_ipv4(self, packet: bytes, ip_source: str) -> None:
        """
        This method parses IPv4 packet and segment on Windows platform.
        """

        ethernet = Ethernet(
            "00:00:00:00:00:00", "00:00:00:00:00:00", 0x0800, packet
        )
        parsed_type = self.ipv4_parse(packet)
        parsed_protocol = getattr(
            self,
            ip_protocols_functions.get(parsed_type.protocol, "unknow_parse"),
        )(parsed_type.data)

        tuple(
            callback(packet, ethernet, parsed_type, parsed_protocol)
            for callback in self.callbacks
        )

    def windows_do_receive_ipv6(self, packet: bytes, ip_source: str) -> None:
        """
        This method parses IPv6 packet and segment on Windows platform.
        """

        ethernet = Ethernet(
            "00:00:00:00:00:00", "00:00:00:00:00:00", 0x86DD, packet
        )
        # parsed_type = self.ipv6_parse(packet)
        ipv6 = IPv6(
            6,
            0,
            0,
            len(packet),
            0x90,
            0,
            ip_source[0],
            "0000:0000:0000:0000:0000:0000:0000:0000",
            packet,
        )
        parsed_protocol = getattr(
            self, ip_protocols_functions.get(ipv6.protocol, "unknow_parse")
        )(ipv6.data)

        tuple(
            callback(packet, ethernet, ipv6, parsed_protocol)
            for callback in self.callbacks
        )

    def linux_do_receive(self, frame: bytes, ip_source: str) -> None:
        """
        This method parses frame, packet and segment on Linux platform.
        """

        ethernet = Ethernet(*self.ethernet_parser(frame))

        if ethernet.type is None:
            return None

        parsed_type = getattr(
            self, ethernet_types_functions.get(ethernet.type, "unknow_parse")
        )(ethernet.data)

        if parsed_type is None:
            return None

        parsed_protocol = getattr(
            self,
            ip_protocols_functions.get(parsed_type.protocol, "unknow_parse"),
        )(parsed_type.data)

        if parsed_protocol is None:
            return None

        tuple(
            callback(frame, ethernet, parsed_type, parsed_protocol)
            for callback in self.callbacks
        )

    @staticmethod
    def ethernet_parser(frame: bytes) -> Tuple[str, str, int, bytes]:
        """
        This method parses ethernet fields in frame.
        """

        destination, source, protocol = unpack("!6s6sH", frame[:14])
        destination = hexlify(destination, b":").decode()
        source = hexlify(source, b":").decode()
        return destination, source, protocol, frame[14:]

    @staticmethod
    def ipv4_parse(packet: bytes) -> IPv4:
        """
        This method parses IP fields in packet.
        """

        (
            version,
            services_fields,
            length,
            identification,
            fragment_offset,
            time_to_live,
            protocol,
            checksum,
            source,
            destination,
        ) = unpack("!ccHHHccH4s4s", packet[:20])
        version = int.from_bytes(version, "big")
        services_fields = int.from_bytes(services_fields, "big")
        time_to_live = int.from_bytes(time_to_live, "big")
        protocol = int.from_bytes(protocol, "big")
        header_length = (version & 0b00001111) * 4
        version >>= 4

        flags = fragment_offset & 0b1110000000000000
        flag_reserved = flags & 0b100  # should be 0
        flag_df = flags & 0b010  # 0 = may fragment, 1 = don't fragment
        flag_mf = flags & 0b001  # 0 = last fragment, 1 = more fragment
        fragment_offset >>= 3

        return IPv4(
            version,
            header_length,
            services_fields,
            length,
            identification,
            IpFlags(flags, flag_reserved, flag_df, flag_mf),
            fragment_offset,
            time_to_live,
            protocol,
            checksum,
            ".".join(str(x) for x in source),
            ".".join(str(x) for x in destination),
            packet[header_length:],
        )

    @staticmethod
    def ipv6_parse(packet: bytes) -> IPv6:
        """
        This method parses IP fields in packet.
        """

        version, length, protocol, hop_limit, source, destination = unpack(
            "!IHcc16s16s", packet[:40]
        )
        protocol = int.from_bytes(protocol, "big")
        hop_limit = int.from_bytes(hop_limit, "big")
        traffic_class = version & 0b00001111111100000000000000000000
        services_codepoint = version & 0b00001111110000000000000000000000
        explicit_congestion_notification = (
            version & 0b00000000001100000000000000000000
        )
        flow_label = version & 0b00000000000011111111111111111111
        version >>= 28

        return IPv6(
            version,
            TrafficClass(
                traffic_class,
                services_codepoint,
                explicit_congestion_notification,
            ),
            flow_label,
            length,
            protocol,
            hop_limit,
            hexlify(source, ":", 2).decode(),
            hexlify(destination, ":", 2).decode(),
            packet[40:],
        )

    @staticmethod
    def tcp_parse(segment: bytes) -> TCP:
        """
        This method parses TCP fields in segment.
        """

        (
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            header_length,
            flags,
            window,
            checksum,
            urgent_pointer,
        ) = unpack("!HHIIccHHH", segment[:20])
        header_length = int.from_bytes(header_length, "big")
        flags = int.from_bytes(flags, "big")
        flag_accurate_ecn = (
            header_length & 0b00000001
        )  # 4 bits headers length, 3 bits reserved
        header_length = (header_length >> 4) * 4
        flag_congestion_window_reduced = flags & 0b10000000
        flag_ecn_echo = flags & 0b01000000
        flag_urgent = flags & 0b00100000
        flag_acknowledgment = flags & 0b00010000
        flag_push = flags & 0b00001000
        flag_reset = flags & 0b00000100
        flag_syn = flags & 0b00000010
        flag_fin = flags & 0b00000001

        return TCP(
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            header_length,
            TcpFlags(
                (flag_accurate_ecn << 8) + flags,
                flag_accurate_ecn,
                flag_congestion_window_reduced,
                flag_ecn_echo,
                flag_urgent,
                flag_acknowledgment,
                flag_push,
                flag_reset,
                flag_syn,
                flag_fin,
            ),
            window,
            checksum,
            urgent_pointer,
            segment[header_length:],
        )

    @staticmethod
    def udp_parse(segment: bytes) -> UDP:
        """
        This method parses UDP fields in segment.
        """

        source_port, destination_port, length, checksum = unpack(
            "!HHHH", segment[:8]
        )

        return UDP(
            source_port,
            destination_port,
            length,
            checksum,
            segment[8:],
        )

    @staticmethod
    def unknow_parse(data: bytes) -> bytes:
        """
        This method parses not implemented types and protocols.
        """

        return Unknow(None, None, None, None, data)


class IpFilter:

    """
    This class implements a IP protocols filter.
    """

    def ethernet_parser(self, frame: bytes) -> Tuple[str, str, int, bytes]:
        """
        This method filters on IP protocols.
        """

        destination, source, type_, data = super().ethernet_parser(frame)

        if type_ == 0x0800 or type_ == 0x86DD:
            return destination, source, type_, data

        return None, None, None, None


class IpsFilter(IpFilter):

    """
    This class implements a sniffer with IPv4
    and IPv6 addresses filters.
    """

    def __init__(
        self,
        *args,
        ip_filters: List[Union[IPv4Address, IPv6Address]] = None,
        **kwargs,
    ):
        ipv4_filters = self.ipv4_filters = []
        add_v4 = ipv4_filters.append
        ipv6_filters = self.ipv6_filters = []
        add_v6 = ipv6_filters.append
        tuple(
            add_v4(str(ip)) if ip.version == 4 else add_v6(str(ip))
            for ip in ip_filters
        )

        if is_windows and ipv6_filters:
            warn("IPv6 addresses filter is not working on Windows.")

        super().__init__(*args, **kwargs)

    def ipv4_parse(self, packet: bytes) -> IPv4:
        """
        This function filters on IPv4 addresses.
        """

        packet = super().ipv4_parse(packet)

        if (
            packet.source in self.ipv4_filters
            or packet.destination in self.ipv4_filters
        ):
            return packet

        return None

    def ipv6_parse(self, packet: bytes) -> IPv6:
        """
        This function filters on IPv6 addresses.
        """

        packet = super().ipv6_parse(packet)

        if (
            packet.source in self.ipv6_filters
            or packet.destination in self.ipv6_filters
        ):
            return packet

        return None


class NetworksFilter(IpFilter):

    """
    This class implements a sniffer with IPv4
    and IPv6 networks filters.
    """

    def __init__(
        self,
        *args,
        network_filters: List[Union[IPv4Network, IPv6Network]] = None,
        **kwargs,
    ):
        networkv4_filters = self.networkv4_filters = []
        add_v4 = networkv4_filters.append
        networkv6_filters = self.networkv6_filters = []
        add_v6 = networkv6_filters.append
        tuple(
            add_v4(network) if network.version == 4 else add_v6(network)
            for network in network_filters
        )

        super().__init__(*args, **kwargs)

    def ipv4_parse(self, packet: bytes) -> IPv4:
        """
        This function filters on IPv4 networks.
        """

        packet = super().ipv4_parse(packet)
        source = ip_address(packet.source)
        destination = ip_address(packet.destination)

        if any(
            destination in n or source in n for n in self.networkv4_filters
        ):
            return packet

        return None

    def ipv6_parse(self, packet: bytes) -> IPv6:
        """
        This function filters on IPv6 networks.
        """

        packet = super().ipv6_parse(packet)

        if (
            ip_address(packet.source) in self.networkv6_filters
            or ip_address(packet.destination) in self.networkv6_filters
        ):
            return packet

        return None


class MacFilter:

    """
    This class implements a filter on MAC addresses.
    """

    def __init__(self, *args, mac_filters: List[str] = None, **kwargs):
        self.mac_filters = mac_filters
        super().__init__(*args, **kwargs)

    def ethernet_parser(self, frame: bytes) -> Tuple[str, str, int, bytes]:
        """
        This method filters on MAC addresses.
        """

        destination, source, protocol, data = super().ethernet_parser(frame)

        if destination in self.mac_filters or source in self.mac_filters:
            return destination, source, protocol, data

        return None, None, None, None


class IPv6Filter:

    """
    This class implements a filter on IPv6.
    """

    def __init__(self, *args, ipv6_filter: bool = False, **kwargs):
        super().__init__(*args, **kwargs)

        self.ipv6s = ()
        self.ipv6_filter = ipv6_filter

    def ethernet_parser(self, frame: bytes) -> Tuple[str, str, int, bytes]:
        """
        This method filters on IPv6.
        """

        destination, source, protocol, data = super().ethernet_parser(frame)

        if protocol == 0x86DD:
            return destination, source, protocol, data

        return None, None, None, None


class IPv4Filter:

    """
    This class implements a filter on IPv4.
    """

    def __init__(self, *args, ipv4_filter: bool = False, **kwargs):
        super().__init__(*args, **kwargs)

        self.ipv4_filter = ipv4_filter
        self.ipv6s = ()

    def ethernet_parser(self, frame: bytes) -> Tuple[str, str, int, bytes]:
        """
        This method filters on IPv4.
        """

        destination, source, protocol, data = super().ethernet_parser(frame)

        if protocol == 0x0800:
            return destination, source, protocol, data

        return None, None, None, None


class PortsFilter(IpFilter):

    """
    This class implements a filter on ports.
    """

    def __init__(self, *args, port_filters: List[int] = None, **kwargs):
        for port in port_filters:
            if 0 > port > 65565:
                raise ValueError(
                    "Port number must be between 0 and "
                    "65565, incorrect value: " + str(port)
                )

        self.port_filters = port_filters

        super().__init__(*args, **kwargs)

    def ipv4_parse(self, packet: bytes) -> IPv4:
        """
        This function filters on IPv4 protocols (TCP or UDP).
        """

        packet = super().ipv4_parse(packet)

        if packet.protocol == 0x06 or packet.protocol == 0x11:
            return packet

        return None

    def ipv6_parse(self, packet: bytes) -> IPv6:
        """
        This function filters on IPv6 protocols (TCP or UDP).
        """

        packet = super().ipv6_parse(packet)

        if packet.protocol == 0x06 or packet.protocol == 0x11:
            return packet

        return None

    def tcp_parse(self, segment: bytes) -> TCP:
        """
        This function filters on ports.
        """

        segment = super().tcp_parse(segment)

        if (
            segment.source in self.port_filters
            or segment.destination in self.port_filters
        ):
            return segment

        return None

    def udp_parse(self, segment: bytes) -> UDP:
        """
        This function filters on ports.
        """

        segment = super().tcp_parse(segment)

        if (
            segment.source in self.port_filters
            or segment.destination in self.port_filters
        ):
            return segment

        return None


class TcpFilter(IpFilter):

    """
    This class implements a filter on TCP (Transmission Control Protocol).
    """

    def __init__(self, *args, tcp_filter: bool = False, **kwargs):
        self.tcp_filter = tcp_filter

        super().__init__(*args, **kwargs)

    def ipv4_parse(self, packet: bytes) -> IPv4:
        """
        This function filters on TCP (Transmission Control Protocol).
        """

        packet = super().ipv4_parse(packet)

        if packet.protocol == 0x06:
            return packet

        return None

    def ipv6_parse(self, packet: bytes) -> IPv6:
        """
        This function filters on TCP (Transmission Control Protocol).
        """

        packet = super().ipv6_parse(packet)

        if packet.protocol == 0x06:
            return packet

        return None


class UdpFilter(IpFilter):

    """
    This class implements a filter on UDP (User Datagram Protocol).
    """

    def __init__(self, *args, udp_filter: bool = False, **kwargs):
        self.udp_filter = udp_filter

        super().__init__(*args, **kwargs)

    def ipv4_parse(self, packet: bytes) -> IPv4:
        """
        This function filters on UDP (User Datagram Protocol).
        """

        packet = super().ipv4_parse(packet)

        if packet.protocol == 0x11:
            return packet

        return None

    def ipv6_parse(self, packet: bytes) -> IPv6:
        """
        This function filters on UDP (User Datagram Protocol).
        """

        packet = super().ipv6_parse(packet)

        if packet.protocol == 0x11:
            return packet

        return None


class WindowsRawSocket:

    """
    This class opens RAW socket on Windows
    (on the layer 3 - IPv4/IPv6).
    """

    def __init__(
        self,
        sniffer: Sniffer,
        ip: Union[Tuple[str, int], Tuple[str, int, int, int]],
        ip_version: int = 4,
    ):
        self.ip_version = ip_version
        self.address = ip[0]
        self.ip = ip

        if ip_version == 4:
            self.type = AF_INET
            self.protocol = IPPROTO_IP
            self.to_get = IP_HDRINCL
            self.do_receive = sniffer.windows_do_receive_ipv4
        elif ip_version == 6:
            self.type = AF_INET6
            self.protocol = IPPROTO_IPV6
            self.to_get = IPV6_PKTINFO
            self.do_receive = sniffer.windows_do_receive_ipv6
        else:
            raise ValueError(
                "IP version (ip_version) must be 4 for IPv4 or 6 for IPv6."
            )

    def __enter__(self) -> WindowsRawSocket:
        self.socket = socket(self.type, SOCK_RAW, IPPROTO_IP)
        self.socket.bind(self.ip)

        self.socket.setsockopt(self.protocol, self.to_get, 0)
        self.socket.ioctl(SIO_RCVALL, RCVALL_ON)
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]] = None,
        exc_value: Optional[BaseException] = None,
        traceback: Optional[TracebackType] = None,
    ) -> bool:
        self.socket.ioctl(SIO_RCVALL, RCVALL_OFF)
        self.socket.close()
        return False


def to_ascii(data: bytes) -> str:
    """
    This function transforms bytes to ascii printables characters.
    """

    return bytes(x if x in printable else 46 for x in data).decode()


def hexadecimal(
    data: bytes,
    frame: Ethernet,
    packet: Union[IPv4, IPv6, Unknow],
    segment: Union[TCP, UDP, Unknow],
    color: bool = True,
) -> None:
    """
    This function prints data as hexadecimal.
    """

    if color:
        y = "\x1b[38;2;227;137;54m"
        v = "\x1b[38;2;42;179;51m"
        b = "\x1b[38;2;50;72;154m"
        reset = "\x1b[0m"
    else:
        reset = y = v = b = ""

    to_print = ""

    for position in range(0, len(data), line_size):
        temp_data = data[position : position + line_size]
        to_print += (
            f"{y}{position:0>4x}  {v}"
            f"{hexlify(temp_data, ' ').decode():<{format_size}}"
            f"  {b}{to_ascii(temp_data)}\n"
        )

    print(to_print + reset, file=file)


def hexadecimal_data(
    data: bytes,
    frame: Ethernet,
    packet: Union[IPv4, IPv6, Unknow],
    segment: Union[TCP, UDP, Unknow],
    color: bool = True,
) -> None:
    """
    This function prints data as hexadecimal.
    """

    hexadecimal(segment.data, frame, packet, segment)


def raw(
    data: bytes,
    frame: Ethernet,
    packet: Union[IPv4, IPv6, Unknow],
    segment: Union[TCP, UDP, Unknow],
) -> None:
    """
    This function prints data as raw.
    """

    file.buffer.write(data)
    file.flush()


def raw_data(
    data: bytes,
    frame: Ethernet,
    packet: Union[IPv4, IPv6, Unknow],
    segment: Union[TCP, UDP, Unknow],
) -> None:
    """
    This function prints data as raw.
    """

    file.buffer.write(segment.data)
    file.flush()


def summary(
    data: bytes,
    frame: Ethernet,
    packet: Union[IPv4, IPv6, Unknow],
    segment: Union[TCP, UDP, Unknow],
    color: bool = True,
) -> None:
    """
    This function prints a frame, packet and segment summary.
    """

    if color:
        y = "\x1b[38;2;227;137;54m"
        v = "\x1b[38;2;42;179;51m"
        b = "\x1b[38;2;50;72;154m"
        reset = "\x1b[0m"
    else:
        reset = y = v = b = ""

    print(
        f"{y}[{ethernet_types[frame.type]} "
        f"{ip_protocols.get(packet.protocol, 'Unknown')}"
        f"{flags_to_string(segment)}][{len(segment.data)}] "
        f"{v}{packet.source or 'Unknown'}({frame.source}):"
        f"{segment.source or 0} -> {b}{packet.destination or 'Unknown'}"
        f"({frame.destination}):{segment.destination or 0}{reset}",
        file=file,
    )


def flags_to_string(segment: Union[TCP, UDP, Unknow]) -> None:
    """
    This function returns a representation of TCP flags.
    """

    flag = getattr(segment, "flags", None)

    if not flag:
        return ""

    flags = "S" if flag.syn else ""
    flags += "A" if flag.acknowledgment else ""
    flags += "P" if flag.push else ""
    flags += "U" if flag.urgent else ""
    flags += "F" if flag.fin else ""
    flags += "R" if flag.reset else ""

    return " Flags: " + flags


def parse_args() -> Namespace:
    """
    This function parses command line arguments.
    """

    parser = ArgumentParser(
        description=(
            "This tool is a pure python multi-platform"
            " sniffer without any external package."
        )
    )

    parser_add_argument = parser.add_argument

    parser_add_argument(
        "--no-hexadecimal",
        "--hexadecimal",
        "-x",
        default=True,
        action="store_false",
        help="Don't print frame, packet and segment as hexadecimal.",
    )
    parser_add_argument(
        "--hexadecimal-data",
        "-X",
        action="store_true",
        help="Print data (not parsed data) as hexadecimal.",
    )
    parser_add_argument(
        "--summary",
        "-s",
        action="store_true",
        help="Print frame, packet and segment summary.",
    )
    parser_add_argument(
        "--raw-data",
        "-R",
        action="store_true",
        help="Print data (not parsed data) as raw.",
    )
    parser_add_argument(
        "--raw",
        "-r",
        action="store_true",
        help="Print frame, packet and segment as raw.",
    )

    protocol = parser.add_mutually_exclusive_group()
    ip_version = parser.add_mutually_exclusive_group()
    output = parser.add_mutually_exclusive_group()

    protocol.add_argument(
        "--tcp",
        "-t",
        action="store_true",
        help="Filter on TCP protocol (Transmission Control Protocol).",
    )
    protocol.add_argument(
        "--udp",
        "-u",
        action="store_true",
        help="Filter on UDP protocol (User Datagram Protocol).",
    )
    ip_version.add_argument(
        "--ipv4",
        "-4",
        action="store_true",
        help="Filter on IPv4 (Internet Protocol version 4).",
    )
    ip_version.add_argument(
        "--ipv6",
        "-6",
        action="store_true",
        help="Filter on IPv6 (Internet Protocol version 6).",
    )
    parser_add_argument(
        "--networks",
        "-n",
        nargs="+",
        action="extend",
        help="Filter on networks (ipv4 and ipv6).",
    )
    parser_add_argument(
        "--ports",
        "-p",
        nargs="+",
        action="extend",
        type=int,
        help="Filter on ports.",
    )
    if not is_windows:
        parser_add_argument(
            "--mac",
            "-m",
            nargs="+",
            action="extend",
            help="Filter on MAC addresses.",
        )
    parser_add_argument(
        "--ip",
        "-i",
        nargs="+",
        action="extend",
        help="Filter on IP addresses.",
    )

    parser_add_argument(
        "--line-size",
        "--line",
        "-l",
        type=int,
        help="Characters number to print in a line (for hexadecimal only)",
    )

    output.add_argument(
        "--color", "-c", action="store_true", help="Colored output."
    )
    output.add_argument(
        "--file",
        "-f",
        default=stdout,
        type=FileType("w"),
        help="File to save output.",
    )
    return parser.parse_args()


def modify_globals(arguments: Namespace) -> None:
    """
    This function modify the script behaviour
    using the command line arguments values.
    """

    global hexadecimal, hexadecimal_data, summary, line_size, file, format_size

    if not arguments.color:
        hexadecimal_data = partial(hexadecimal_data, color=False)
        hexadecimal = partial(hexadecimal, color=False)
        summary = partial(summary, color=False)

    if arguments.line_size:
        line_size = arguments.line_size
        format_size = line_size * 2 + line_size - 1

    file = arguments.file


def get_callbacks(arguments: Namespace) -> List[Callable]:
    """
    This function defined callbacks with
    command line arguments values.
    """

    callbacks = []
    add = callbacks.append

    if arguments.no_hexadecimal:
        add(hexadecimal)
    if arguments.hexadecimal_data:
        add(hexadecimal_data)
    if arguments.raw:
        add(raw)
    if arguments.raw_data:
        add(raw_data)
    if arguments.summary:
        add(summary)

    return callbacks


def get_addresses() -> Tuple[List[IPv4Address], List[IPv6Address]]:
    """
    This function returns all addresses.
    """

    if not is_windows:
        return None, None

    ips = getaddrinfo(gethostname(), 0)
    ipv4s = []
    ipv6s = []
    add_v4 = ipv4s.append
    add_v6 = ipv6s.append

    for ip in ips:
        if ip[0] == AF_INET6:
            add_v6(ip[-1])
        elif ip[0] == AF_INET:
            add_v4(ip[-1])

    return ipv4s, ipv6s


def get_snifferfilters(arguments: Namespace) -> Tuple[type, Dict[str, Any]]:
    """
    This function returns a class to build
    the Sniffer with Filters and keyword arguments
    to use it.
    """

    class_ = Sniffer
    kwargs = {}
    subclasses = []

    if arguments.tcp:
        subclasses.append(class_)
        class_ = TcpFilter
    elif arguments.udp:
        subclasses.append(class_)
        class_ = UdpFilter

    if arguments.ipv4:
        subclasses.append(class_)
        class_ = IPv4Filter
    elif arguments.ipv6:
        subclasses.append(class_)
        class_ = IPv6Filter

    if arguments.networks:
        subclasses.append(class_)
        class_ = NetworksFilter
        kwargs["network_filters"] = [ip_network(x) for x in arguments.networks]

    if arguments.ports:
        subclasses.append(class_)
        class_ = PortsFilter
        kwargs["port_filters"] = arguments.ports

    if not is_windows and arguments.mac:
        subclasses.append(class_)
        class_ = MacFilter
        kwargs["mac_filters"] = arguments.mac

    if arguments.ip:
        subclasses.append(class_)
        class_ = IpsFilter
        kwargs["ip_filters"] = [ip_address(x) for x in arguments.ip]

    if subclasses:
        subclasses.append(class_)
        subclasses.reverse()
        class_ = new_class("SnifferFilters", tuple(subclasses), {})

    return class_, kwargs


def main() -> int:
    """
    The main function to starts this script from command line.
    """

    arguments = parse_args()
    modify_globals(arguments)

    callbacks = get_callbacks(arguments)
    ipv4s, ipv6s = get_addresses()

    SnifferFilters, kwargs = get_snifferfilters(arguments)

    sniffer = SnifferFilters(ipv4s, ipv6s, callbacks, **kwargs)
    sniffer.sniff()

    return 0


if __name__ == "__main__":
    exit(main())
