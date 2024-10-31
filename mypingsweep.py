#!/usr/bin/python

import sys
import netaddr
import logging
import sys, os
import argparse
import concurrent.futures
import threading
import time
from scapy.all import send, sendp, IP, ICMP, AsyncSniffer
from alive_progress import alive_bar

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


PING_TIMEOUT = 3
TOTAL_TIMEOUT = 10 # se for 40ms por ping, deveria ser network.size*0.04.
ESTIMATED_LATENCY_MS = 20
INTER = 0.005
COUNT = 3
PING_SIZE = 56

def meuping(lista_ips):
	mydata = threading.local()
	mydata.res = {}
	mydata.Raw = 'Mypingsweep: veni, vidi, vici!'
	mydata.Raw = mydata.Raw + '#'*(PING_SIZE - len(mydata.Raw.encode('utf-8')))

	with alive_bar(len(lista_ips), title='Pingando', bar='blocks', spinner='triangles') as bar:	# Para mostrar barra de progresso do alive_bar

		start_t = time.time()
		for ip in lista_ips:
			# Send & wait for response for the ICMP Echo Request packet
			#print('ping %s'%ip)

			if (sys.platform == 'linux'):
				reply = sendp( IP(dst=str(ip)) / ICMP() / mydata.Raw, return_packets=True, verbose=False, realtime = True, inter = INTER, count = COUNT )
			else:
				reply = sendp( IP(dst=str(ip)) / ICMP() / mydata.Raw, return_packets=True, verbose=False, realtime = True, inter = INTER, count = COUNT )
			mydata.res['%s'%ip] = reply[0][IP].time
			bar() #alive_bar
		end_t = time.time()
	print("Pingou %d enderecos em %s"%(len(lista_ips),calcula_tempo(end_t-start_t)))
	return(mydata.res)

def prepara_end_rede(end_rede):
	aux = end_rede.split(".")
	aa = ''
	while aux[-1] == '0':
		aux.pop(-1)
	for i in aux:
		aa = aa + i + '.'
	return(aa.rstrip("."))

def calcula_tempo(interval_secs):
	if interval_secs > 3600:
		t_h = interval_secs // 3600
		t_m = (interval_secs % 3600) // 60
		t_s = ((interval_secs % 3600) // 60) % 60
		res = ("%3.2fh:%3.2fm:%3.2fs"%(t_h, t_m, t_s))
	elif TOTAL_TIMEOUT > 60:
		t_m = interval_secs // 60
		t_s = interval_secs % 60
		res = ("%3.2fm:%3.2fs"%(t_m, t_s))
	else:
		t_s = interval_secs
		res = ("%3.2fs"%(t_s))

	return(res)

	
if __name__ == '__main__':
	print('\tMy Ping Sweep\n')
	parser = argparse.ArgumentParser(description="Ping sweeper v2 customizado.")
	parser.add_argument('-net', '-net_addr', dest="net_addr", help="Endereco de rede (bloco) com mascara para teste.")
	# Exemplo: python mymypingsweep.py -net 177.22.0.0/16

	args = parser.parse_args()
	
	net = args.net_addr

	responding = []
	network = netaddr.IPNetwork(net)
	n_size = network.size
	TOTAL_TIMEOUT = 2 * COUNT * INTER * n_size

#	print("Vai esperar %s para receber respostas"%calcula_tempo(TOTAL_TIMEOUT))
	print("Iniciando")	

	sniff_results = [] 
	l_ips = []
	for ip in network:
		if ip == network.network or ip == network.broadcast:
			continue

		l_ips.append(ip)

	# Iniciando sniffer antes mesmo de enviar primeiro ping, para garantir que nao perdemos resposta
	net_str = prepara_end_rede("%s"%(network.network))
	flt = ("icmp and src net %s"%net_str)  # Filtro para pegar so respostas da rede que estamos varrendo
	#print(flt)
	#sniffer = AsyncSniffer(prn=lambda x: x.summary(), filter=flt, count=len(l_ips),timeout=TOTAL_TIMEOUT)
	#sniffer = AsyncSniffer(prn=lambda x: x.summary(), filter=flt, count=len(l_ips))
	sniffer = AsyncSniffer(prn=lambda x: x.summary(), filter=flt)

	sniffer.start()

	# Vamos preparar e iniciar thread de envio dos pings 
	t_ping = concurrent.futures.ThreadPoolExecutor(max_workers=1) 	# Pool de threads com 1 worker
	ping_results = t_ping.submit(meuping, l_ips) 						# Submetendo funcao ao pool de threads e inicia o mesmo

	#sniffer.join()  # Isso bloqueia o programa principal no sniffer, ate que todos os pacotes (count) sejam capturados, ou timeout aconteca
	#sniff_results = sniffer.results

	t_ping.shutdown(wait=True)		# Para programa ate thread que envia pings termine - para obter resultados.
	
	ping_result_dict = ping_results.result()

	time.sleep(5)
	sniffer.stop()
	sniff_results = sniffer.results

	n_respostas = 0
	for i in range(len(sniff_results)):
		if (i == 0):
			print("Resposta de: %s em %3.2f ms"%(sniff_results[i][IP].src, sniff_results[i][IP].time - ping_result_dict[sniff_results[i][IP].src]))  # sniff_results[i][IP].time
			n_respostas += 1
		elif (sniff_results[i][IP].src != sniff_results[i-1][IP].src):
			print("Resposta de: %s em %3.2f ms"%(sniff_results[i][IP].src, sniff_results[i][IP].time - ping_result_dict[sniff_results[i][IP].src]))  # sniff_results[i][IP].time
			n_respostas += 1
		
	print('[+] %d IPs responderam ICMP Echo.'%n_respostas)


