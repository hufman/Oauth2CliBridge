import requests
import json
import time
from . import _requests

class NeedsAuthentication(Exception):
	""" User needs to visit the Oauth2 Bridge """
	def __init__(self, url):
		Exception.__init__(self, url)
		self.location = url
		
	pass

class BridgeClient(object):
	def __init__(self, bridge_uri, client_id, client_secret, \
	             auth_uri, token_uri, scope, verify=True):
		self.bridge_uri = bridge_uri
		self.client_id = client_id
		self.client_secret = client_secret
		self.auth_uri = auth_uri
		self.token_uri = token_uri
		self.scope = scope
		self.verify = verify
		self.access_token = None
		self.expiration = None

		self.load_access_token()

	def load_access_token(self, force=True):
		post_data = {'client_id':self.client_id,
		             'client_secret':self.client_secret,
		             'auth_uri':self.auth_uri,
		             'token_uri':self.token_uri,
		             'scope':self.scope,
		             'force_new_access':force
		}
		uri = self.bridge_uri
		if uri[-6:] != '/token':
			uri = uri + '/token'
		handle = requests.post(uri, data=post_data, verify=self.verify)
		if int(handle.status_code/100) == 2:
			data = handle.json()
			self.access_token = data['access_token']
			if 'expires_in' in data:
				self.expiration = time.time() + int(data['expires_in'])
		elif handle.status_code == 400:
			raise KeyError(handle.text)
		else:
			raise NeedsAuthentication(handle.headers['Location'])

	def __getattr__(self, name):
		if name == 'requests':
			return _requests.RequestsAdapter(self)
		raise AttributeError(name)
