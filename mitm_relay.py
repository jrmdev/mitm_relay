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
from optparse import OptionParser
from select import select

BIND_WEBSERVER = ('127.0.0.1', 49999)
BUFSIZE = 4096

__prog_name__ = 'mitm_relay'
__version__ = 0.2

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
		help='Create new relays. Several relays can be created at once. Format: -r lport:rhost:rport [-r lport:rhost:rport ...]',
		required=True)

	parser.add_argument('-p', '--proxy',
		action='store',
		metavar='<proxy>',
		dest='proxy',
		help='Proxy to forward all requests/responses to. If omitted, will run in monitoring only. Format: host:port',
		default=False)

	parser.add_argument('-c', '--cert',
		action='store',
		metavar='<cert>',
		dest='cert',
		type=argparse.FileType('r'),
		help='Certificate file to use for SSL/TLS interception',
		default=False, required=True)

	parser.add_argument('-k', '--key',
		action='store',
		metavar='<key>',
		dest='key',
		type=argparse.FileType('r'),
		help='Private key file to use for SSL/TLS interception',
		default=False, required=True)

	cfg = parser.parse_args()
	cfg.prog_name = __prog_name__

	relays = [item for sublist in cfg.relays for item in sublist]

	cfg.relays = []
	for r in relays:
		r = r.split(':')
		try:
			cfg.relays.append((int(r[0]), r[1], int(r[2])))
		except:
			sys.exit('Invalid relay specification, see help.')

	try:
		# There is no point starting the local web server
		# if we are not going to intercept the req/resp (monitor only).
		if cfg.proxy:
			start_ws()

		server_threads = []
		for relay in cfg.relays:
			server_threads.append(Thread(target=create_server, args=(relay, cfg)))

		for t in server_threads:
			t.setDaemon(True)
			t.start()
			time.sleep(.2)

		while True:
			time.sleep(1)

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

	def hexdump(src, l=0x10):
		res = []
		sep = '.'
		src = str(src)

		for i in range(0, len(src), l):
			s = src[i:i+l]
			hexa = ''

			for h in range(0,len(s)):
				if h == l/2:
					hexa += ' '
				h = s[h]
				if not isinstance(h, int):
					h = ord(h)
				h = hex(h).replace('0x','')
				if len(h) == 1:
					h = '0'+h
				hexa += h + ' '

			hexa = hexa.strip()
			text = ''

			for c in s:
				if not isinstance(c, int):
					c = ord(c)

				if 0x20 <= c < 0x7F:
					text += chr(c)
				else:
					text += sep

			res.append(('%08X:  %-'+str(l*(2+1)+1)+'s  |%s|') % (i, hexa, text))

		return '\n'.join(res)

	if all(c in string.printable for c in data):
		return data

	else:
		return '\n'+hexdump(data)

# STARTTLS interception code based on:
# https://github.com/ipopov/starttls-mitm

def do_relay(client_sock, server_sock, cfg):
  server_sock.settimeout(1.0)   
  client_sock.settimeout(1.0)

  ws = '%s:%d' % (BIND_WEBSERVER[0], BIND_WEBSERVER[1])
  remote = '%s/%d' % server_sock.getpeername()
  rport = server_sock.getpeername()[1]
  headers = {u'User-Agent': None, u'Accept': None, u'Accept-Encoding': None, u'Connection': None}

  while True:

	# Peek for the beginnings of an ssl handshake
	try:
		packet = client_sock.recv(BUFSIZE, socket.MSG_PEEK | socket.MSG_DONTWAIT)

		if packet.startswith('\x16\x03'): # SSL/TLS Handshake.

			print color('------------------ Wrapping sockets ------------------', 2)
			client_sock = ssl.wrap_socket(client_sock, server_side=True, suppress_ragged_eofs=True, certfile=cfg.cert.name, keyfile=cfg.key.name)
			server_sock = ssl.wrap_socket(server_sock, suppress_ragged_eofs=True)
 
	except:
		pass

	receiving, _, _ = select([client_sock, server_sock], [], [])

	if client_sock in receiving:
		data_out = client_sock.recv(BUFSIZE)

		if not len(data_out): # client closed connection
			print "[+] Client disconnected", client_sock.getpeername()
			client_sock.close()
			server_sock.close()
			break

		# Modify traffic here
		# Send to your own parser function etc, example:
		# data_out = data_out.replace('hello world', 'goodbye world')

		# or send out to our echo-back webserver through proxy for modification:
		if cfg.proxy:
			data_out = requests.post('http://%s/CLIENT_REQUEST/to/%s' % (ws, remote), proxies={'http': cfg.proxy}, headers=headers, data=data_out).content

		print "C >> S", color('[port %d]' % rport, 4), len(data_out), color(data_repr(data_out), 3, 1), "\n"
		server_sock.send(data_out)

 	if server_sock in receiving:
		data_in = server_sock.recv(BUFSIZE)

		if not len(data_in): # server closed connection
			print "[+] Server disconnected", server_sock.getpeername()
			client_sock.close()
			server_sock.close()
			break

		# Modify traffic here (see example above)
		if cfg.proxy:
			data_in = requests.post('http://%s/SERVER_RESPONSE/from/%s' % (ws, remote), proxies={'http': cfg.proxy}, headers=headers, data=data_in).content

		print "S >> C", color('[port %d]' % rport, 4), len(data_in), color(data_repr(data_in), 3), "\n"
		client_sock.send(data_in)

def handle_client(clientsock, target, cfg):
	targetsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	targetsock.connect(target)

	do_relay(clientsock, targetsock, cfg)

def create_server(relay, cfg):

	serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	serv.bind((cfg.listen, relay[0]))
	serv.listen(2)
	
	print '[+] Relay listening on %d -> %s:%d' % relay
	
	while True:
		client, addr = serv.accept()
		dest_str = '%s:%d' % (relay[1], relay[2])

		print '[+] New client:', addr, "->", color(dest_str, 4)
		thread = Thread(target=handle_client, args=(client, (relay[1], relay[2]), cfg))
		thread.start()

if __name__=='__main__': 
	main()
