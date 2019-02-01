#!/usr/bin/env python

import sys
import socket
import ssl
import os
import requests
import argparse
import time
import string

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from select import select

BIND_WEBSERVER = ('127.0.0.1', 49999)
BUFSIZE = 4096

__prog_name__ = 'mitm_relay'
__version__ = 0.4

def main():
	parser = argparse.ArgumentParser(description='%s version %.2f' % (__prog_name__, __version__))
	
	parser.add_argument('-l', '--listen',
		action='store',
		metavar='<listen>',
		dest='listen',
		help='Address the relays will listen on. Default: 0.0.0.0',
		default='0.0.0.0')

	parser.add_argument('-r', '--relay',
		action='append',
		nargs='+',
		metavar='<relay>',
		dest='relays',
		help='''Create new relays.
			Several relays can be created by repeating the paramter.
			If the protocol is omitted, TCP will be assumed.
			Format: [udp:|tcp:]lport:rhost:rport''',
		required=True)

	parser.add_argument('-s', '--script',
		action='store',
		metavar='<script>',
		dest='script',
		type=argparse.FileType('r'),
		help='''Python script implementing the handle_request() and 
			handle_response() functions (see example). They will be
			called before forwarding traffic to the proxy, if specified.''',
		default=False)

	parser.add_argument('-p', '--proxy',
		action='store',
		metavar='<proxy>',
		dest='proxy',
		help='''Proxy to forward all requests/responses to.
			If omitted, traffic will only be printed to the console
			(monitoring mode unless a script is specified).
			Format: host:port''',
		default=False)

	parser.add_argument('-c', '--cert',
		action='store',
		metavar='<cert>',
		dest='cert',
		type=argparse.FileType('r'),
		help='Certificate file to use for SSL/TLS interception',
		default=False)

	parser.add_argument('-k', '--key',
		action='store',
		metavar='<key>',
		dest='key',
		type=argparse.FileType('r'),
		help='Private key file to use for SSL/TLS interception',
		default=False)
	
	parser.add_argument('-cc', '--clientcert',
		action='store',
		metavar='<clientcert>',
		dest='clientcert',
		type=argparse.FileType('r'),
		help='Client certificate file to use for connecting to server',
		default=False)

	parser.add_argument('-ck', '--clientkey',
		action='store',
		metavar='<clientkey>',
		dest='clientkey',
		type=argparse.FileType('r'),
		help='Client private key file to use for connecting to server',
		default=False)

	cfg = parser.parse_args()
	cfg.prog_name = __prog_name__

	relays = [item for sublist in cfg.relays for item in sublist]

	cfg.relays = []
	for r in relays:
		r = r.split(':')

		try:
			if len(r) == 3:
				cfg.relays.append(('tcp', int(r[0]), r[1], int(r[2])))
			elif len(r) == 4 and r[0] in ['tcp', 'udp']:
				cfg.relays.append((r[0], int(r[1]), r[2], int(r[3])))
			else:
				raise

			if r[0] == 'udp' and cfg.listen.startswith('127.0.0'):
				print color("[!] In UDP, it's not recommended to bind to 127.0.0.1. If you see errors, try to bind to your LAN IP address instead.", 1)

		except:
			sys.exit('[!] error: Invalid relay specification, see help.')

	if not (cfg.cert and cfg.key):
		print color("[!] Server cert/key not provided, SSL/TLS interception will not be available.", 1)
	
	if not (cfg.clientcert and cfg.clientkey):
		print color("[!] Client cert/key not provided.", 1)

	# There is no point starting the local web server
	# if we are not going to intercept the req/resp (monitor only).
	if cfg.proxy:
		start_ws()
	else:
		print color("[!] Interception disabled! %s will run in monitoring mode only." % __prog_name__, 1)

	# If a script was specified, import it
	if cfg.script:
		try:
			from imp import load_source
			cfg.script_module = load_source(cfg.script.name, cfg.script.name)

		except Exception as e:
			print color("[!] %s" % str(e))
			sys.exit()

	server_threads = []
	for relay in cfg.relays:
		server_threads.append(Thread(target=create_server, args=(relay, cfg)))

	for t in server_threads:
		t.setDaemon(True)
		t.start()
		time.sleep(.2)

	while True:
		try:
			time.sleep(100)

		except KeyboardInterrupt:
			sys.exit("\rExiting...")

class RequestHandler(BaseHTTPRequestHandler):

	def do_GET(self):
		
		content_length = self.headers.getheaders('content-length')
		length = int(content_length[0]) if content_length else 0
		body = self.rfile.read(length)

		self.send_response(200)
		self.end_headers()
		self.wfile.write(body)
		return

	def log_message(self, format, *args):
		return

	do_POST = do_GET
	do_PUT = do_GET
	do_DELETE = do_GET

def start_ws():
	print '[+] Webserver listening on', BIND_WEBSERVER
	server = HTTPServer(BIND_WEBSERVER, RequestHandler)

	try:
		t = Thread(target=server.serve_forever)
		t.daemon = True
		t.start()

	except KeyboardInterrupt:
		server.shutdown()

def color(txt, code = 1, modifier = 0):
  return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def data_repr(data):

	def hexdump(src, length=0x10):
		lines = []
		for c in xrange(0, len(src), length):

			lines.append("%08x:  %-*s  |%s|\n" % 
				(c, length*3, 
				' '.join('%02x' % ord(x) for x in src[c:c+length]), 
				''.join(x if 0x20 < ord(x) < 0x7f else '.' for x in src[c:c+length]))
			)
		
		return ''.join(lines)

	if all(c in string.printable for c in data):
		return '\n'+data

	else:
		return '\n'+hexdump(data)

# STARTTLS interception code based on:
# https://github.com/ipopov/starttls-mitm
def do_relay_tcp(client_sock, server_sock, cfg):
	server_sock.settimeout(1.0)   
	client_sock.settimeout(1.0)

	server_peer = server_sock.getpeername()
	client_peer = client_sock.getpeername()

	while True:

		# Peek for the beginnings of an ssl handshake
		try:
			packet = client_sock.recv(BUFSIZE, socket.MSG_PEEK | socket.MSG_DONTWAIT)

			if packet.startswith('\x16\x03'): # SSL/TLS Handshake.

				if not (cfg.cert and cfg.key):
					print color("[!] SSL/TLS handshake detected, provide a server cert and key to enable interception.", 1)
				
				else:
					print color('------------------ Wrapping sockets ------------------', 2)
					client_sock = ssl.wrap_socket(client_sock, server_side=True, suppress_ragged_eofs=True, certfile=cfg.cert.name, keyfile=cfg.key.name)
					
					# Use client-side cert/key if provided.
					if (cfg.clientcert and cfg.clientkey):
						server_sock = ssl.wrap_socket(server_sock, suppress_ragged_eofs=True, certfile=cfg.clientcert.name, keyfile=cfg.clientkey.name)
					else:
						server_sock = ssl.wrap_socket(server_sock, suppress_ragged_eofs=True)
		except:
			pass

		receiving, _, _ = select([client_sock, server_sock], [], [])


		try:
			if client_sock in receiving:
				data_out = client_sock.recv(BUFSIZE)

				if not len(data_out): # client closed connection
					print "[+] Client disconnected", client_peer
					client_sock.close()
					server_sock.close()
					break

				data_out = proxify(data_out, cfg, client_peer, server_peer, to_server=True)
				server_sock.send(data_out)

		 	if server_sock in receiving:
				data_in = server_sock.recv(BUFSIZE)

				if not len(data_in): # server closed connection
					print "[+] Server disconnected", server_peer
					client_sock.close()
					server_sock.close()
					break

				data_in = proxify(data_in, cfg, client_peer, server_peer, to_server=False)
				client_sock.send(data_in)

		except socket.error as e:
			print color("[!] %s" % str(e))

def do_relay_udp(relay_sock, server, cfg):

	client = None

	while True:

		receiving, _, _ = select([relay_sock], [], [])

		if relay_sock in receiving:

			data, addr = relay_sock.recvfrom(BUFSIZE)

			if addr == server:
				data = proxify(data, cfg, client, server, to_server=False)
				relay_sock.sendto(data, client)

			else:
				client = addr
				data = proxify(data, cfg, client, server, to_server=True)
				relay_sock.sendto(data, server)

def proxify(message, cfg, client_peer, server_peer, to_server=True):

	def get_response():
		try:
			return requests.post('http://%s:%d/%s/%s/%d' % 
				(BIND_WEBSERVER[0], BIND_WEBSERVER[1],
				('CLIENT_REQUEST/to' if to_server else 'SERVER_RESPONSE/from'),
				server_peer[0], server_peer[1]),
				proxies={'http': cfg.proxy},
				headers=headers,
				data=message).content

		except requests.exceptions.ProxyError:
			print color("[!] error: can't connect to proxy!", 1)
			return message
	"""
	Modify traffic here
	Send to our own parser functions, to the proxy, or both.
	"""

	server_str = color('%s:%d' % server_peer, 4, 1)
	client_str = color('%s:%d' % client_peer, 6, 1)
	date_str = color(time.strftime("%a %d %b %H:%M:%S", time.gmtime()), 5, 1)
	modified_str = color('(modified!)', 2, 1)
	modified = False

	if cfg.script:
		new_message = message
		
		if to_server and hasattr(cfg.script_module, 'handle_request'):
			new_message = cfg.script_module.handle_request(message)

		if not to_server and hasattr(cfg.script_module, 'handle_response'):
			new_message = cfg.script_module.handle_response(message)

		if new_message == None:
			print color('[!] Error: make sure handle_request and handle_response both return a message.', 1)
			new_message = message

		if new_message != message:
			modified = True
			message = new_message

	if cfg.proxy:
		headers = {u'User-Agent': None, u'Accept': None, u'Accept-Encoding': None, u'Connection': None}
		headers['X-Mitm_Relay-To'] = '%s:%d' % (server_peer if to_server else client_peer)
		headers['X-Mitm_Relay-From'] = '%s:%d' % (client_peer if to_server else server_peer)

		new_message = get_response()

		if new_message != message:
			modified = True
			message = new_message

	if to_server:
		msg_str = color(data_repr(message), 3, 1)
		print "C >> S [ %s >> %s ] [ %s ] [ %d ] %s %s\n" % (client_str, server_str, date_str, len(message), modified_str if modified else '', msg_str)

	else:
		msg_str = color(data_repr(message), 3, 0)
		print "S >> C [ %s >> %s ] [ %s ] [ %d ] %s %s\n" % (server_str, client_str, date_str, len(message), modified_str if modified else '', msg_str)

	return message

def handle_tcp_client(client_sock, target, cfg):
	server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_sock.connect(target)
	do_relay_tcp(client_sock, server_sock, cfg)

def create_server(relay, cfg):
	proto, lport, rhost, rport = relay

	if proto == 'tcp':
		serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		serv.bind((cfg.listen, lport))
		serv.listen(2)
	
		print '[+] Relay listening on %s %d -> %s:%d' % relay
		
		while True:
			if proto == 'tcp':
				client, addr = serv.accept()
				dest_str = '%s:%d' % (relay[2], relay[3])
			
				print '[+] New client:', addr, "->", color(dest_str, 4)
				thread = Thread(target=handle_tcp_client, args=(client, (rhost, rport), cfg))
				thread.start()
	else:
		serv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		serv.bind((cfg.listen, lport))

		thread = Thread(target=do_relay_udp, args=(serv, (rhost, rport), cfg))
		thread.start()

if __name__=='__main__': 
	main()
