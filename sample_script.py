def handle_request(client_request):
	"""
	This function will be called when a request is received from the client.
	It must return the request to be forwarded to the server (or proxy if specified).
	"""

	modified_request = client_request.replace(b'original', b'modified')

	return modified_request

def handle_response(server_response):
	"""
	This function will be called when a response is received from the server.
	It must return the response to be fowarded to the client (or proxy if specified).
	"""

	modified_response = server_response.replace(b'example', b'testing')

	return modified_response
