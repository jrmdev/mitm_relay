#!/usr/bin/env python3

import sys
import socket
import ssl
import os
import requests
import argparse
import time
import string

from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from select import select

BIND_WEBSERVER = ('127.0.0.1', 49999)
BUFSIZE = 2048

__prog_name__ = 'mitm_relay'
__version__ = 2.5

def p(txt, fg=32, bg=49, ret=False):
	s = "\033[1;%d;%dm%s\033[0m" % (fg, bg, txt) if 'win' not in sys.platform else txt
	if ret:
		return s
	print(s)

class RequestHandler(BaseHTTPRequestHandler):

	def do_GET(self):
		content_length = int(self.headers.get('content-length'))
		body = self.rfile.read(content_length)

		self.send_response(200)
		self.end_headers()
		self.wfile.write(body)
		return

	def log_message(self, format, *args):
		return

	do_POST = do_GET
	do_PUT = do_GET
	do_DELETE = do_GET

class MitmRelay():

	def __init__(self, cfg):

		self.cfg = cfg
		self.relays = []

		for r in [x[0] for x in self.cfg.relays]:
			r = r.split(':')

			if len(r) == 3:
				self.relays.append(('tcp', int(r[0]), r[1], int(r[2])))

			elif len(r) == 4 and r[0] in ['tcp', 'udp']:
				self.relays.append((r[0], int(r[1]), r[2], int(r[3])))

			else:
				raise ValueError("Invalid relay specification")

			if r[0] == 'udp' and self.cfg.listen.startswith('127.0.0'):
				p("[!] In UDP, it's not recommended to bind to 127.0.0.1. If you see errors, try to bind to your LAN IP address instead.", 1, 31)

		if not (self.cfg.cert and self.cfg.key):
			p("[!] Server cert/key not provided, SSL/TLS interception will not be available. To generate certs, see provided script 'gen_certs.sh'.", 1, 31)

		# There is no point starting the local web server
		# if we are not going to intercept the req/resp (monitor only).
		if self.cfg.proxy:
			if 'http://' not in self.cfg.proxy:
				self.cfg.proxy = 'http://%s' % self.cfg.proxy
			self.start_ws()
		else:
			p("[!] Interception disabled! %s will run in monitoring mode only." % __prog_name__, 0, 31)

		# If a script was specified, import it
		if self.cfg.script:
			try:
				from imp import load_source
				self.cfg.script_module = load_source(self.cfg.script.name, self.cfg.script.name)

			except Exception as e:
				p("[!] %s" % str(e), 1, 31)
				sys.exit()

		server_threads = []
		for relay in self.relays:
			t = Thread(target=self.create_server, args=(relay, ))
			server_threads.append(t)

		for t in server_threads:
			t.daemon = True
			t.start()

		while True:
			try:
				time.sleep(100)

			except KeyboardInterrupt:
				sys.exit("\rExiting...")

	def data_repr(self, data):

		def hexdump(src, length=16):
			result = []
			digits = 2

			s = src[:]
			for i in range(0, len(s), length):
				hexa = " ".join(["%0*X" % (digits, x) for x in src[i:i+length]])
				text = "".join([chr(x) if 0x20 <= x < 0x7F else "." for x in s[i:i+length]])
				result.append("%08x:  %-*s  |%s|\n" % (i, length * (digits + 1), hexa, text))

			return "".join(result)

		try:
			data = data.decode("ascii")
			return '\n'+data

		except:
			return '\n'+hexdump(data)

	def start_ws(self):
		print('[+] Webserver listening on', BIND_WEBSERVER)
		server = HTTPServer(BIND_WEBSERVER, RequestHandler)

		try:
			t = Thread(target=server.serve_forever)
			t.daemon = True
			t.start()

		except KeyboardInterrupt:
			server.shutdown()

	def wrap_sockets(self, client_sock, server_sock):

		if not (self.cfg.cert and self.cfg.key):
			p("[!] SSL/TLS handshake detected, provide a server cert and key to enable interception.", 1, 31)
		
		else:
			p('---------------------- Wrapping sockets ----------------------', 1, 32)

			ctx1 = ssl._create_unverified_context(ssl.PROTOCOL_TLS_SERVER)
			ctx1.check_hostname = False
			ctx1.verify_mode = ssl.CERT_NONE
			ctx1.load_cert_chain(certfile=self.cfg.cert.name, keyfile=self.cfg.key.name)
			tls_sock_to_client = ctx1.wrap_socket(client_sock, server_side=True, suppress_ragged_eofs=True, do_handshake_on_connect=False)#, suppress_ragged_eofs=False)

			ctx2 = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
			ctx2.check_hostname = False
			ctx2.verify_mode = ssl.CERT_NONE
			
			if self.cfg.clientcert and self.cfg.clientkey:
				ctx2.load_cert_chain(certfile=self.cfg.clientcert.name, keyfile=self.cfg.clientkey.name)

			tls_sock_to_server = ctx2.wrap_socket(server_sock, server_side=False, suppress_ragged_eofs=True, do_handshake_on_connect=False)#, suppress_ragged_eofs=False)

			return tls_sock_to_client, tls_sock_to_server

		return client_sock, server_sock

	def do_relay_tcp(self, client_sock, server_sock):
		server_sock.settimeout(self.cfg.timeout)
		client_sock.settimeout(self.cfg.timeout)

		server_peer = server_sock.getpeername()
		client_peer = client_sock.getpeername()

		while True:

			receiving, x, y = select([client_sock, server_sock], [], [])

			try:
				if client_sock in receiving:

					# Peek for the beginning of a TLS session
					if not isinstance(client_sock, ssl.SSLSocket):
						peek = client_sock.recv(BUFSIZE, socket.MSG_PEEK)
						if peek.startswith(b'\x16\x03'):
							client_sock, server_sock = self.wrap_sockets(client_sock, server_sock)

					data_out = client_sock.recv(BUFSIZE)

					if not len(data_out):
						print("[+] Client disconnected", client_peer)
						client_sock.close()
						server_sock.close()
						break

					data_out = self.proxify(data_out, client_peer, server_peer, to_server=True)
					server_sock.send(data_out)

				if server_sock in receiving:

					data_in = server_sock.recv(BUFSIZE)

					if not len(data_in):
						print("[+] Server disconnected", server_peer)
						client_sock.close()
						server_sock.close()
						break

					data_in = self.proxify(data_in, client_peer, server_peer, to_server=False)
					client_sock.send(data_in)

			except TimeoutError as e:
				p("[!] %s" % str(e), 1, 31)

			#except socket.error as e:
			#	p("[!] %s" % str(e), 1, 31)


	def do_relay_udp(self, relay_sock, server):

		client = None

		while True:

			receiving, _, _ = select([relay_sock], [], [])

			if relay_sock in receiving:

				data, addr = relay_sock.recvfrom(BUFSIZE)

				if addr == server:
					data = self.proxify(data, client, server, to_server=False)
					relay_sock.sendto(data, client)

				else:
					client = addr
					data = self.proxify(data, client, server, to_server=True)
					relay_sock.sendto(data, server)

	def proxify(self, message, client_peer, server_peer, to_server=True):

		def get_response():
			try:
				host = f"{BIND_WEBSERVER[0]}:{BIND_WEBSERVER[1]}"
				peer = f"{server_peer[0]}:{server_peer[1]}"
				uri = 'CLIENT_REQUEST/to' if to_server else 'SERVER_RESPONSE/from'
				response = requests.post('http://%s/%s/%s' % (host, uri, peer), proxies={'http': self.cfg.proxy}, headers=headers, data=message)
				return response.content

			except requests.exceptions.ProxyError:
				p("[!] error: can't connect to proxy!", 1, 31)
				return message
		"""
		Modify traffic here
		Send to our own parser functions, to the proxy, or both.
		"""

		server_str = p('%s:%d' % server_peer, 1, 34, True)
		client_str = p('%s:%d' % client_peer, 1, 36, True)
		date_str = p(time.strftime("%a %d %b %H:%M:%S", time.gmtime()), 1, 35, True)
		modified_str = p('(modified!)', 1, 32, True)
		modified = False

		if self.cfg.script:
			new_message = message

			if to_server and hasattr(cfg.script_module, 'handle_request'):
				new_message = cfg.script_module.handle_request(message)

			if not to_server and hasattr(cfg.script_module, 'handle_response'):
				new_message = cfg.script_module.handle_response(message)

			if new_message == None:
				p("[!] Error: make sure handle_request and handle_response both return a message.", 1, 31)
				new_message = message

			if new_message != message:
				modified = True
				message = new_message

		if self.cfg.proxy:
			headers = {u'User-Agent': None, u'Accept': None, u'Accept-Encoding': None, u'Connection': None}
			host = f"{BIND_WEBSERVER[0]}:{BIND_WEBSERVER[1]}"
			peer = f"{server_peer[0]}:{server_peer[1]}"
			uri = 'CLIENT_REQUEST/to' if to_server else 'SERVER_RESPONSE/from'

			try:
				response = requests.post('http://%s/%s/%s' % (host, uri, peer), proxies={'http': self.cfg.proxy}, headers=headers, data=message)
				new_message = response.content

			except requests.exceptions.ProxyError:
				p("[!] error: can't connect to proxy!", 1, 31)
				return

			if new_message != message:
				modified = True
				message = new_message

		if to_server:
			msg_str = p(self.data_repr(message), 0, 93, True)
			print("C >> S [ %s >> %s ] [ %s ] [ %d ] %s %s" % (client_str, server_str, date_str, len(message), modified_str if modified else '', msg_str))

		else:
			msg_str = p(self.data_repr(message), 0, 33, True)
			print("S >> C [ %s >> %s ] [ %s ] [ %d ] %s %s" % (server_str, client_str, date_str, len(message), modified_str if modified else '', msg_str))

		return message

	def handle_tcp_client(self, client_sock, target):
		try:
			# The client sock is actually a server (mitm_relay listener)
			# The server sock is actually a client (socket to dest server)
			server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_sock.connect(target)
			self.do_relay_tcp(client_sock, server_sock)

		except ConnectionRefusedError as e:
			p('[!] Unable to connect to server: %s' % str(e), 1, 31)

	def create_server(self, relay):
		proto, lport, rhost, rport = relay

		if proto == 'tcp':
			try:
				serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				serv.bind((self.cfg.listen, lport))
				serv.listen(2)
			except OSError as e:
				p('[!] Error: %s:%d %s' % (self.cfg.listen, lport, str(e)), 1, 31)
				return

			print('[+] Relay listening on %s %d -> %s:%d' % relay)

			while True:
				client, addr = serv.accept()
				dest_str = '%s:%d' % (relay[2], relay[3])

				p('[+] New client %s:%d will be relayed to %s' % (addr[0], addr[1], dest_str), 1, 39)
				thread = Thread(target=self.handle_tcp_client, args=(client, (rhost, rport)))
				thread.start()
		else:
			serv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
			serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			serv.bind((self.cfg.listen, lport))

			thread = Thread(target=self.do_relay_udp, args=(serv, (rhost, rport)))
			thread.start()

if __name__ == "__main__":

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

	parser.add_argument('-t', '--timeout',
		action='store',
		metavar='<timeout>',
		dest='timeout',
		type=int,
		help='Socket connection timeout',
		default=3.0)

	cfg = parser.parse_args()
	cfg.prog_name = __prog_name__

	relay = MitmRelay(cfg)
