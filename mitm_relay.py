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
from urllib.parse import urlsplit

__prog_name__ = 'mitm_relay'
__version__ = 3.00
__webserver_port__ = 49999

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
		self.cfg.bind_ws = (self.cfg.webserver_bind, __webserver_port__)
		self.cfg.recv_bufsize = 2048
		self.relays = []

		for relay_spec in self.iter_relay_specs():
			relay = self.parse_relay_spec(relay_spec)
			self.relays.append(relay)

			if relay[0] == 'udp' and self.cfg.listen.startswith('127.0.0'):
				p("[!] In UDP, it's not recommended to bind to 127.0.0.1. If you see errors, try to bind to your LAN IP address instead.", 1, 31)

		if not (self.cfg.cert and self.cfg.key):
			p("[!] Server cert/key not provided, SSL/TLS interception will not be available. To generate certs, see provided script 'gen_certs.sh'.", 1, 31)

		# There is no point starting the local web server
		# if we are not going to intercept the req/resp (monitor only).
		if self.cfg.proxy:
			self.cfg.proxy_url, self.cfg.proxy_host, self.cfg.proxy_type = self.normalize_proxy(self.cfg.proxy)

			self.cfg.ws_host = f"{self.cfg.bind_ws[0]}:{self.cfg.bind_ws[1]}"
			self.start_ws()

			p("[i] Client <> Server communications will be relayed via proxy %s" % self.cfg.proxy_url, 0, 32)

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

	def iter_relay_specs(self):
		for relay_group in self.cfg.relays:
			for relay_spec in relay_group:
				yield relay_spec

	def parse_relay_spec(self, relay_spec):
		relay_parts = relay_spec.split(':')

		if len(relay_parts) == 3:
			return ('tcp', int(relay_parts[0]), relay_parts[1], int(relay_parts[2]))

		if len(relay_parts) == 4 and relay_parts[0] in ['tcp', 'udp']:
			return (relay_parts[0], int(relay_parts[1]), relay_parts[2], int(relay_parts[3]))

		raise ValueError("Invalid relay specification")

	def normalize_proxy(self, proxy):
		proxy_url = proxy if '://' in proxy else 'http://%s' % proxy
		parsed = urlsplit(proxy_url)

		if not parsed.scheme or not parsed.netloc:
			raise ValueError("Invalid proxy specification")

		return proxy_url, parsed.netloc, parsed.scheme

	def start(self):
		server_threads = []
		for relay in self.relays:
			t = Thread(target=self.create_server, args=(relay, ))
			t.daemon = True
			server_threads.append(t)

		for thread in server_threads:
			thread.start()

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

	def close_socket(self, sock):
		try:
			sock.shutdown(socket.SHUT_RDWR)
		except OSError:
			pass

		try:
			sock.close()
		except OSError:
			pass

	def close_connection(self, *sockets):
		for sock in sockets:
			if sock is not None:
				self.close_socket(sock)

	def send_all(self, sock, data):
		if data:
			sock.sendall(data)

	def format_peer(self, peer):
		if peer is None:
			return 'unknown'

		return '%s:%d' % peer

	def build_proxy_request(self, message, server_peer, to_server):
		peer = self.format_peer(server_peer)
		uri = 'CLIENT_REQUEST/to' if to_server else 'SERVER_RESPONSE/from'
		request = urllib.request.Request('http://%s/%s/%s' % (self.cfg.ws_host, uri, peer), data=message)
		request.set_proxy(self.cfg.proxy_host, self.cfg.proxy_type)
		request.has_header = lambda x: True
		return request

	def do_relay_tcp(self, client_sock, server_sock):
		server_sock.settimeout(self.cfg.timeout)
		client_sock.settimeout(self.cfg.timeout)

		server_peer = server_sock.getpeername()
		client_peer = client_sock.getpeername()

		while True:

			try:
				receiving, _, _ = select.select([client_sock, server_sock], [], [], self.cfg.timeout)

				if not receiving:
					raise socket.timeout('timed out')

				# Peek for the beginning of a TLS session
				if client_sock in receiving and not isinstance(client_sock, ssl.SSLSocket) and client_sock.recv(2, socket.MSG_PEEK) == b'\x16\x03':
					client_sock, server_sock = self.wrap_sockets(client_sock, server_sock)
					continue

				if client_sock in receiving:

					data_out = client_sock.recv(self.cfg.recv_bufsize)

					if not len(data_out):
						print("[+] Client disconnected", client_peer)
						break

					data_out = self.proxify(data_out, client_peer, server_peer, to_server=True)
					self.send_all(server_sock, data_out)

				if server_sock in receiving:

					data_in = server_sock.recv(self.cfg.recv_bufsize)

					if not len(data_in):
						print("[+] Server disconnected", server_peer)
						break

					data_in = self.proxify(data_in, client_peer, server_peer, to_server=False)
					self.send_all(client_sock, data_in)

			except ssl.SSLWantReadError:
				pass

			except (BrokenPipeError, ConnectionResetError, OSError, socket.timeout, TimeoutError) as e:
				p("[!] %s" % str(e), 1, 31)
				break

		self.close_connection(client_sock, server_sock)

	def do_relay_udp(self, relay_sock, server):

		client = None

		while True:

			receiving, _, _ = select.select([relay_sock], [], [])

			if relay_sock in receiving:

				data, addr = relay_sock.recvfrom(self.cfg.recv_bufsize)

				if addr == server:
					if client is None:
						continue

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

		server_str = p(self.format_peer(server_peer), 1, 34, True)
		client_str = p(self.format_peer(client_peer), 1, 36, True)
		date_str = p(time.strftime("%a %d %b %H:%M:%S", time.gmtime()), 1, 35, True)
		modified_str = p('(modified!)', 1, 32, True)

		if self.cfg.script:

			if to_server and hasattr(self.cfg.script_module, 'handle_request'):
				message = self.cfg.script_module.handle_request(message)

			if not to_server and hasattr(self.cfg.script_module, 'handle_response'):
				message = self.cfg.script_module.handle_response(message)

			if message == None:
				p("[!] Error: make sure handle_request and handle_response both return a message.", 1, 31)
				message = orig_message

		if self.cfg.proxy:
			try:
				with urllib.request.urlopen(self.build_proxy_request(message, server_peer, to_server)) as u:
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
					self.close_connection(sock_to_client, sock_to_server)

				else:
					thread = Thread(target=self.do_relay_tcp, args=(sock_to_client, sock_to_server))
					thread.daemon = True
					thread.start()

		else:
			try:
				relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
				relay_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				relay_sock.bind((self.cfg.listen, lport))
			except OSError as e:
				p('[!] Error: %s:%d %s' % (self.cfg.listen, lport, str(e)), 1, 31)
				return

			print('[+] Relay listening on %s %d -> %s:%d' % relay)

			thread = Thread(target=self.do_relay_udp, args=(relay_sock, (rhost, rport)))
			thread.daemon = True
			thread.start()

def build_parser():
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
		default=120)

	parser.add_argument('--webserver-bind',
		action='store',
		metavar='<addr>',
		dest='webserver_bind',
		help='Address the internal webserver will bind on. Useful if the proxy is on a different host. Default: 127.0.0.1',
		default='127.0.0.1')

	return parser

if __name__ == "__main__":

	parser = build_parser()

	cfg = parser.parse_args()
	cfg.prog_name = __prog_name__

	mitm_relay = MitmRelay(cfg)
	mitm_relay.start()
