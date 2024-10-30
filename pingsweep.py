#!/usr/bin/python

'''
>>> conf.ifaces
Source   Index  Name                              MAC                IPv4             IPv6
libpcap  1      Software Loopback Interface 1     00:00:00:00:00:00  127.0.0.1        ::1
libpcap  11     WAN Miniport (IP)
libpcap  16     Intel(R) Wi-Fi 7 BE200 320MHz #2  a2:b3:39:74:7f:52  169.254.11.250   fe80::9ff9:9af3:8bc4:9b75
libpcap  19     Intel(R) Wi-Fi 7 BE200 320MHz     Intel:74:7f:52     169.254.169.106  fe80::6ece:9c0b:c8e3:e5db
libpcap  21     Bluetooth Device (Personal Area_  Intel:74:7f:56     169.254.135.30   fe80::6329:2be0:f879:8980
libpcap  3      WAN Miniport (Network Monitor)
libpcap  30     DW5932e-eSIM Snapdragon X62 5G    Qualcomm:00:00:01  100.67.32.127    fe80::3ac2:ed6e:d739:8c73
                                                                                      2804:214:816c:c343:88ca:435d:2d2_
                                                                                      2804:214:816c:c343:7171:515b:d80_
                                                                                      2804:214:816c:c343:9392:4338:9b7_
libpcap  31     WAN Miniport (IPv6)
libpcap  6      Intel(R) Wi-Fi 7 BE200 320MHz #4  Intel:74:7f:53     169.254.17.39    fe80::6808:2c5a:6907:76b7
>>> conf.iface
<NetworkInterface_Win DW5932e-eSIM Snapdragon X62 5G [UP+RUNNING+WIRELESS+OK]>
'''

import sys
import netaddr
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sr1, IP, ICMP

PING_TIMEOUT = 3
IFACE='eth0'

if __name__ == '__main__':
	print '\tQuick Ping Sweep\n'

	if len(sys.argv) != 2:
		print '[?] Usage: pingsweep <network>'
		sys.exit(0)
	
	net = sys.argv[1]
	print 'Input network:', net

	responding = []
	network = netaddr.IPNetwork(net)

	for ip in network:
		if ip == network.network or ip == network.broadcast:
			continue

		# Send & wait for response for the ICMP Echo Request packet
		reply = sr1( IP(dst=str(ip)) / ICMP(), timeout=PING_TIMEOUT, iface=IFACE, verbose=0 )

		if not reply:
			continue

		if int(reply.getlayer(ICMP).type) == 0 and int(reply.getlayer(ICMP).code) == 0:
			print(ip, ': Host is responding to ICMP Echo Requests.')
			responding.append(ip)

	print('[+] Spotted {} ICMP Echo Requests.'.format(len(responding)))