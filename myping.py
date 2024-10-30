#!/usr/bin/env python
"""
raw = abcdefghijklmnopqrstuvwabcdefghi
p = import_hexcap('4500003c0d0400008001f396644c1f769f8a16da08004ce6000100756162636465666768696a6b6c6d6e6f7071727374757677616263646566676869')
e = Ether(p)
p = IP(P)
ic = ICMP(p)

"""
import platform
import sys
import argparse
from scapy.all import *

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Ping customizado para testar ECN.")
	parser.add_argument('-ip', '-ip_addr', dest="ip_addr", help="Endereco IP de destino.")
	parser.add_argument('-ecn', '-ecn_value', dest="ecn_ip", type=int, default = 0x01, help="Valor do ecn a ser usado.")
	parser.add_argument('-n', '--nping', dest="num_ping", type=int, default = 1, help="Numero de pings a enviar.")
	# Exemplo: python myping.py -ip 159.138.22.218 -ecn 2 -n 5

	args = parser.parse_args()
	TOUT = 5

	ip = IP()
	ip.dst = args.ip_addr
	ip.tos=args.ecn_ip
	icmp = ICMP()
	icmp.type = 8 #echo request
	icmp.code = 0
	icmp.id = 0x0001
	icmp.sequence=0x00b1
	raw = 'ping do Atila testando ECN......'
	#raw = 'abcdefghijklmnopqrstuvwabcdefghi'
	pkt = ip/icmp/raw
	#pkts=[p for p in pkt]

	print("Enviando ping com pacotes:")
	print(pkt)
	if (sys.platform == 'linux'):
		#ans, unans = sr(pkt, timeout=TOUT, inter = 0.5)  # loop=1
		ans, unans = srloop(pkt, timeout = TOUT, inter = 0.5, count = args.num_ping)
	else:
		#ans, unans = srp(pkt, timeout = TOUT, inter = 0.5) # precisa ser sendp  em windows
		ans, unans = srploop(pkt, timeout = TOUT, inter = 0.5, count = args.num_ping)
		#ans, unans = srploop(ip/ICMP(type=8, code=0, id=0x0001, seq=(0x00b1, 0x00b5))/raw, timeout = TOUT, inter = 0.5, count = 5)

	print(ans)
	print(unans)   
	if len(ans) > 0:
		print(ans.summary())
		for j in range(len(ans)):
			#ans[j].query.show()
			rtt = 1000 * (ans[j].answer[IP].time - ans[j].query[IP].sent_time)
			print("Query: IP TOS = %02X, ICMP Type = %d, bytes = %d, TTL = %d"%(ans[j].query[IP].tos, ans[j].query[ICMP].type, len(ans[j].query[Raw].load), ans[j].query[IP].ttl))
			print("Answer: TOS = %02X, ICMP Type = %d, byte = %d, TTL = %d, em %3.2f ms"%(ans[j].answer[IP].tos, ans[j].answer[ICMP].type, ans[j].answer[IP].ttl, len(ans[j].answer[Raw].load), rtt))
		


	#r2 = srploop(pkt, count=5, timeout = 5)

