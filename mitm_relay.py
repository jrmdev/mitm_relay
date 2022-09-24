#!/usr/bin/env python3

import sys
import socket
import select
import ssl
import argparse
import time
import urllib.request

from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from urllib.error import URLError

__prog_name__ = 'mitm_relay'
__version__ = 3.00

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
		self.cfg.bind_ws = ('127.0.0.1', 49999)
		self.cfg.recv_bufsize = 2048
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

			handler = urllib.request.ProxyHandler({"http": self.cfg.proxy})
			opener = urllib.request.build_opener(handler)
			urllib.request.install_opener(opener)
			
			self.cfg.ws_host = f"{self.cfg.bind_ws[0]}:{self.cfg.bind_ws[1]}"
			self.cfg.ws_req = urllib.request.Request('http://')
			self.cfg.ws_req.set_proxy(self.cfg.proxy, 'http')
			self.cfg.ws_req.has_header = lambda x: True
			self.start_ws()

			p("[i] Client <> Server communications will be relayed via proxy %s" % self.cfg.proxy, 0, 32)

		else:
			p("[i] Proxy not specified! %s will run in monitoring mode only." % __prog_name__, 0, 32)

		# If a script was specified, import it
		if self.cfg.script:
			try:
				from imp import load_source
				self.cfg.script_module = load_source(self.cfg.script.name, self.cfg.script.name)

			except Exception as e:
				p("[!] %s" % str(e), 1, 31)
				sys.exit()

	def start(self):
		server_threads = []
		for relay in self.relays:
			t = Thread(target=self.create_server, args=(relay, ))
			t.daemon = True
			server_threads.append(t)

		[t.start() for t in server_threads]

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
			return '\n'+data.decode("ascii")

		except:
			return '\n'+hexdump(data)

	def start_ws(self):
		p('[i] Webserver listening on %s:%d' % self.cfg.bind_ws, 0, 32)
		server = HTTPServer(self.cfg.bind_ws, RequestHandler)

		try:
			t = Thread(target=server.serve_forever)
			t.daemon = True
			t.start()

		except KeyboardInterrupt:
			server.shutdown()

	def wrap_sockets(self, client_sock, server_sock):

		if not (self.cfg.cert and self.cfg.key):
			p("[!] SSL/TLS handshake detected, provide a server cert and key to enable interception.", 0, 31)
			return client_sock, server_sock
		
		try:
			p('---------------------- Wrapping sockets ----------------------', 1, 32)

			# Wrapping mitm_relay listener socket to client
			client_ctx = ssl._create_unverified_context(ssl.PROTOCOL_TLS_SERVER)
			client_ctx.check_hostname = False
			client_ctx.verify_mode = ssl.CERT_NONE
			client_ctx.load_cert_chain(certfile=self.cfg.cert.name, keyfile=self.cfg.key.name)

			tls_sock_to_client = client_ctx.wrap_socket(client_sock, server_side=True, suppress_ragged_eofs=True, do_handshake_on_connect=True)

			# wrapping mitm_relay client socket to server
			server_ctx = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
			server_ctx.check_hostname = False
			server_ctx.verify_mode = ssl.CERT_NONE
			
			if self.cfg.clientcert and self.cfg.clientkey:
				server_ctx.load_cert_chain(certfile=self.cfg.clientcert.name, keyfile=self.cfg.clientkey.name)

			tls_sock_to_server = server_ctx.wrap_socket(server_sock, server_side=False, suppress_ragged_eofs=True, do_handshake_on_connect=True)
			tls_sock_to_server.setblocking(0)

			return tls_sock_to_client, tls_sock_to_server

		except ssl.SSLError as e:
			p("[!] %s" % str(e), 1, 31)
			sys.exit(1)

	def do_relay_tcp(self, client_sock, server_sock):
		server_sock.settimeout(self.cfg.timeout)
		client_sock.settimeout(self.cfg.timeout)

		server_peer = server_sock.getpeername()
		client_peer = client_sock.getpeername()

		while True:

			receiving, x, y = select.select([client_sock, server_sock], [], [])

			# Peek for the beginning of a TLS session
			if client_sock in receiving and not isinstance(client_sock, ssl.SSLSocket) and client_sock.recv(2, socket.MSG_PEEK) == b'\x16\x03':
				client_sock, server_sock = self.wrap_sockets(client_sock, server_sock)

			try:
				if client_sock in receiving:

					data_out = client_sock.recv(self.cfg.recv_bufsize)

					if not len(data_out):
						print("[+] Client disconnected", client_peer)
						server_sock.shutdown(1)
						break

					data_out = self.proxify(data_out, client_peer, server_peer, to_server=True)
					server_sock.send(data_out)

				if server_sock in receiving:

					data_in = server_sock.recv(self.cfg.recv_bufsize)

					if not len(data_in):
						print("[+] Server disconnected", server_peer)
						client_sock.shutdown(1)
						break

					data_in = self.proxify(data_in, client_peer, server_peer, to_server=False)
					client_sock.send(data_in)

			except ssl.SSLWantReadError:
				pass

			except (ConnectionResetError, TimeoutError) as e:
				p("[!] %s" % str(e), 1, 31)

	def do_relay_udp(self, relay_sock, server):

		client = None

		while True:

			receiving, _, _ = select.select([relay_sock], [], [])

			if relay_sock in receiving:

				data, addr = relay_sock.recvfrom(self.cfg.recv_bufsize)

				if addr == server:
					data = self.proxify(data, client, server, to_server=False)
					relay_sock.sendto(data, client)

				else:
					client = addr
					data = self.proxify(data, client, server, to_server=True)
					relay_sock.sendto(data, server)

	def proxify(self, message, client_peer, server_peer, to_server=True):

		orig_message = message

		"""
		Modify traffic here by modifying the 'message' variable.
		Optionally, send it to our own parser functions, to the proxy, or both.

		message = message.replace(b'example.com', b'mysite.com')
		"""

		server_str = p('%s:%d' % server_peer, 1, 34, True)
		client_str = p('%s:%d' % client_peer, 1, 36, True)
		date_str = p(time.strftime("%a %d %b %H:%M:%S", time.gmtime()), 1, 35, True)
		modified_str = p('(modified!)', 1, 32, True)

		if self.cfg.script:

			if to_server and hasattr(cfg.script_module, 'handle_request'):
				message = cfg.script_module.handle_request(message)

			if not to_server and hasattr(cfg.script_module, 'handle_response'):
				message = cfg.script_module.handle_response(message)

			if message == None:
				p("[!] Error: make sure handle_request and handle_response both return a message.", 1, 31)
				message = orig_message

		if self.cfg.proxy:
			peer = f"{server_peer[0]}:{server_peer[1]}"
			uri = 'CLIENT_REQUEST/to' if to_server else 'SERVER_RESPONSE/from'

			try:
				self.cfg.ws_req.full_url = 'http://%s/%s/%s' % (self.cfg.ws_host, uri, peer)
				self.cfg.ws_req.data = message

				with urllib.request.urlopen(self.cfg.ws_req) as u:
					message = u.read()
			
			except URLError as e:
				p("[!] Could not connect to proxy: %s" % str(e), 1, 31)
				sys.exit(1)

		if to_server:
			msg_str = p(self.data_repr(message), 0, 93, True)
			print("C >> S [ %s >> %s ] [ %s ] [ %d ] %s %s" % (client_str, server_str, date_str, len(message), modified_str if message != orig_message else '', msg_str))

		else:
			msg_str = p(self.data_repr(message), 0, 33, True)
			print("S >> C [ %s >> %s ] [ %s ] [ %d ] %s %s" % (server_str, client_str, date_str, len(message), modified_str if message != orig_message else '', msg_str))

		return message

	def create_server(self, relay):
		proto, lport, rhost, rport = relay

		if proto == 'tcp':
			try:
				relay_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				relay_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				relay_sock.bind((self.cfg.listen, lport))
				relay_sock.listen(2)
			except OSError as e:
				p('[!] Error: %s:%d %s' % (self.cfg.listen, lport, str(e)), 1, 31)
				return

			print('[+] Relay listening on %s %d -> %s:%d' % relay)

			while True:
				sock_to_client, addr = relay_sock.accept()

				p('[+] New client %s:%d will be relayed to %s:%d' % (addr[0], addr[1], relay[2], relay[3]), 1, 39)

				try:
					sock_to_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					sock_to_server.connect((rhost, rport))

				except (socket.gaierror, ConnectionRefusedError) as e:
					p('[!] Unable to connect to server: %s' % str(e), 1, 31)

				else:
					thread = Thread(target=self.do_relay_tcp, args=(sock_to_client, sock_to_server))
					thread.daemon = True
					thread.start()

		else:
			relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
			relay_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			relay_sock.bind((self.cfg.listen, lport))

			print('[+] Relay listening on %s %d -> %s:%d' % relay)

			thread = Thread(target=self.do_relay_udp, args=(relay_sock, (rhost, rport)))
			thread.daemon = True
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
		help='Socket receive timeout',
		default=3.0)

	cfg = parser.parse_args()
	cfg.prog_name = __prog_name__

	mitm_relay = MitmRelay(cfg)
	mitm_relay.start()
