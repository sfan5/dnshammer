#!/usr/bin/env python3
import sys
import ipaddress

for line in sys.stdin:
	line = line.rstrip("\r\n")
	if not line: break
	ip = ipaddress.IPv6Address(line)
	print(ip.reverse_pointer + ".\tPTR")
