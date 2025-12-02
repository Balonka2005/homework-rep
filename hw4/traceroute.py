import sys
import time
import socket
import argparse
import re
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.sendrecv import sr1
conf.verb = 0


class WhoisClient:

    def __init__(self):
        self.root_server = "whois.arin.net"
        self.port = 43

    def get_as_number(self, ip):
        try:
            query = f"n + {ip}\r\n"
            response = self._send_query(self.root_server, query)

            asn = self._parse_asn(response)
            if asn:
                return asn

            referral = self._get_referral(response)
            if referral:
                query = f"{ip}\r\n"
                response = self._send_query(referral, query)
                asn = self._parse_asn(response)
                return asn

        except Exception:
            return None
        return None

    def _send_query(self, server, query):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((server, self.port))
            s.send(query.encode())
            buff = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                buff += data
            return buff.decode('utf-8', errors='ignore')
        finally:
            s.close()

    def _get_referral(self, text):
        match = re.search(r"ReferralServer:\s*whois://([\w.-]+)", text, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def _parse_asn(self, text):

        match = re.search(r"(?:OriginAS|origin|aut-num):\s*(AS\d+)", text, re.IGNORECASE)
        if match:
            return match.group(1)

        return None


def create_packet(protocol, target_ip, ttl, port, is_ipv6):
    if is_ipv6:
        l3 = IPv6(dst=target_ip, hlim=ttl)
    else:
        l3 = IP(dst=target_ip, ttl=ttl)

    if protocol == 'icmp':
        if is_ipv6:
            l4 = ICMPv6EchoRequest()
        else:
            l4 = ICMP()
    elif protocol == 'tcp':
        l4 = TCP(dport=port, flags="S", seq=100)
    elif protocol == 'udp':
        l4 = UDP(dport=port)
    else:
        return None

    return l3 / l4


def get_response(packet, timeout):
    start_time = time.time()
    ans = sr1(packet, verbose=0, timeout=timeout)
    end_time = time.time()

    if ans:
        rtt = (end_time - start_time) * 1000
        return ans, rtt
    return None, None


def is_ipv6_address(ip):
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        return False


def main():
    parser = argparse.ArgumentParser(description="Custom Traceroute", add_help=False)

    parser.add_argument("ip_address", help="Target IP address")
    parser.add_argument("protocol", choices=["tcp", "udp", "icmp"], help="Protocol to use")

    parser.add_argument("-t", type=float, default=2.0, help="Timeout in seconds")
    parser.add_argument("-p", type=int, default=80, help="Port (for tcp/udp)")
    parser.add_argument("-n", type=int, default=30, help="Max hops")
    parser.add_argument("-v", action="store_true", help="Verbose (Show AS number)")

    try:
        args = parser.parse_args()
    except SystemExit:
        print("Usage: traceroute [OPTIONS] IP_ADDRESS {tcp|udp|icmp}")
        sys.exit(1)

    target = args.ip_address
    proto = args.protocol
    max_hops = args.n
    timeout = args.t
    port = args.p
    show_as = args.v

    is_ipv6 = is_ipv6_address(target)


    whois = WhoisClient()

    print(f"Traceroute to {target}, {max_hops} hops max, protocol {proto.upper()}")

    for ttl in range(1, max_hops + 1):
        pkt = create_packet(proto, target, ttl, port, is_ipv6)

        reply, rtt = get_response(pkt, timeout)

        output_parts = [f"{ttl}"]

        if reply is None:
            output_parts.append("*")
        else:
            if is_ipv6:
                src_ip = reply.src
            else:
                src_ip = reply.src

            output_parts.append(f"{src_ip}")
            output_parts.append(f"[{rtt:.2f}ms]")

            if show_as:
                is_private = False
                if not is_ipv6:
                    if src_ip.startswith("10.") or src_ip.startswith("192.168."):
                        is_private = True
                    elif src_ip.startswith("172."):
                        second_octet = int(src_ip.split('.')[1])
                        if 16 <= second_octet <= 31:
                            is_private = True

                if not is_private:
                    asn = whois.get_as_number(src_ip)
                    if asn:
                        output_parts.append(f"[{asn}]")

        print(" ".join(output_parts))

        if reply:
            if proto == 'icmp':
                if is_ipv6:
                    if reply.haslayer(ICMPv6EchoReply):
                        break
                else:
                    if reply.type == 0:
                        break


            else:
                if reply.src == target:
                    break


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges (sudo).")
        sys.exit(1)
    main()