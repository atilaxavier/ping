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
import platform
import sys, os
import argparse
import concurrent.futures
import threading
#from atpbar import flush
#from scapy.all import *
from scapy.all import sr1, srp1, sr, srp, IP, ICMP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


PING_TIMEOUT = 1
IFACE='eth0'

def meuping(lista_ips):
	mydata = threading.local()
	mydata.res = []
	mydata.Raw = 'Mypingsweep: veni, vidi, vici!'

	print("Nome do worker thread: %s. Recebeu %d IPs para pingar"%(threading.current_thread().name, len(lista_ips)))
	for ip in lista_ips:
		
		# Send & wait for response for the ICMP Echo Request packet
		print('ping %s'%ip)
		#reply = sr1( IP(dst=str(ip)) / ICMP(), timeout=PING_TIMEOUT, verbose=0 )
		if (sys.platform == 'linux'):
			reply, noreply = sr( IP(dst=str(ip)) / ICMP() / mydata.Raw, timeout=PING_TIMEOUT, verbose=0 )
		else:
			reply, noreply = srp( IP(dst=str(ip)) / ICMP() / mydata.Raw, timeout=PING_TIMEOUT, verbose=0 )

		if not reply:
			continue
		#print(reply[-1])
		if int(reply[-1][ICMP].type) == 0 and int(reply[-1][ICMP].code) == 0:
			rtt = 1000 * (reply[-1].answer[IP].time - reply[-1].query[IP].sent_time)
			print('%s: Host esta respondendo ICMP Echo Requests em %3.2f'%(ip, rtt))
			mydata.res.append([ip, rtt])
	
	return(mydata.res)

if __name__ == '__main__':
	print('\tMy Ping Sweep thread\n')
	parser = argparse.ArgumentParser(description="Ping sweeper customizado.")
	parser.add_argument('-net', '-net_addr', dest="net_addr", help="Endereco de rede (bloco) com mascara para teste.")
	# Exemplo: python mymypingsweep.py -net 177.22.0.0/16

	args = parser.parse_args()
	
	net = args.net_addr

	responding = []
	network = netaddr.IPNetwork(net)
	n_size = network.size
	

	n_cpu = os.cpu_count()
	print("Numero de CPUs na maquina: %d\n"%n_cpu) # para usarmos como quantidade de threads
	pool = concurrent.futures.ThreadPoolExecutor(max_workers=n_cpu)
	t_results = [None] * n_cpu
	l_ips = []
	for ip in network:
		if ip == network.network or ip == network.broadcast:
			continue

		l_ips.append(ip)
	#len(l_ips) # quantidade total de IPs a pingar
	n_ips_thread = len(l_ips)//n_cpu	# IPs por thread

	for i in range(n_cpu):
		# i*n_ips_thread:(i*n_ips_thread)+n_ips_thread
		t_results[i] = pool.submit(meuping, l_ips[i*n_ips_thread:(i*n_ips_thread)+n_ips_thread])

	pool.shutdown(wait=True)

	for i in range(n_cpu):
		if(t_results[i].result() != None) & (len(t_results[i].result())>0):
			for j in range(len(t_results[i].result())):
				responding.append(t_results[i].result()[j])
				print("Resposta de: %s em %3.2f"%(t_results[i].result()[j][0], t_results[i].result()[j][1]))
		
	print('[+] %d IPs responderam ICMP Echo.'%len(responding))
	#print(responding)
