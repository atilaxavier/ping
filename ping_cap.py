#!/usr/bin/env python

import argparse
from datetime import datetime
from scapy.all import *


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Ping capture")
	parser.add_argument('-ip', '-ip_addr', dest="ip_addr", default='201.36.80.57', help="Endereco IP dos pacotes a capturar.")
	args = parser.parse_args()

	ip = args.ip_addr
	#flt = ("icmp")
	flt = ("icmp and host %s"%ip)
	#flt = ("icmp and dst host %s"%ip)
	#flt = ("icmp and dst net 201.36.80.0")


	try:
		#t = AsyncSniffer(prn=lambda x: x.summary(), filter=flt, store=False)
		#datetime.now()
		t = AsyncSniffer(prn=lambda x: ("%s"%datetime.now()+": "+x.summary()+" ttl:%s"%x[IP].ttl+" tos:%02X"%x[IP].tos+" HexData: "+x[Raw].load.hex()+" StrData: %s"%x[Raw].load) if(x[IP].proto==1) else x.summary(), filter=flt, store=False)
		t.start()
		#time.sleep(20)
		#t.stop()
		t.join()  # this will hold until count packets are collected

	except KeyboardInterrupt:
		t.stop()
		print("Interrompido pelo usuario")
		pass
