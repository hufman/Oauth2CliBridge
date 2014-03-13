from nose.tools import *
import time
import subprocess
import socket
import requests
import urllib
import urlparse
import json
import re

import sys
sys.path.append('lib/oauth2testserver/')
from oauth2clibridge.client import BridgeClient, NeedsAuthentication
import os


class TestClientManually:
	@classmethod
	def setup_class(klass):
		flaskenv = dict(os.environ)
		flaskenv['DEBUG'] = "False"
		devnull = open('/dev/null', 'w')
		klass.server = subprocess.Popen(['python','-m','oauth2testserver.main'], stderr=devnull, stdout=devnull, cwd='lib/oauth2testserver')
		klass.bridge = subprocess.Popen(['python','-m','oauth2clibridge.server.main'], stderr=devnull, stdout=devnull, env=flaskenv)
		attempts = 20
		while attempts > 0 and not klass.is_ready(('127.0.0.1',9873)):
			time.sleep(0.2)
			attempts -= 1
		attempts = 20
		while attempts > 0 and not klass.is_ready(('127.0.0.1',5000)):
			time.sleep(0.2)
			attempts -= 1
	@staticmethod
	def is_ready(address):
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(.1)
			sock.connect(address)
		except socket.error:
			return False
		except socket.timeout:
			return False
		return True
		
	def setup(self):
		client_id,client_secret = self.generate_client()
		self.args = self.generate_args(client_id, client_secret)
	def teardown(self):
		requests.delete('http://127.0.0.1:9873/client', \
		                data={'client_id':self.args['client_id'],
		                      'client_secret':self.args['client_secret']})
		self.delete_auths()

	@staticmethod
	def generate_client():
		resp = requests.post('http://127.0.0.1:9873/client')
		data = json.loads(resp.text)
		return (data['client_id'], data['client_secret'])

	@staticmethod
	def generate_args(client_id, client_secret):
		args = {'bridge_uri': 'http://127.0.0.1:5000/token',
		        'client_id': client_id,
		        'client_secret': client_secret,
		        'auth_uri': 'http://127.0.0.1:9873/auth',
		        'token_uri': 'http://127.0.0.1:9873/token',
		        'validate_uri': 'http://127.0.0.1:9873/validate',
		        'scope': 'test'
		}
		return args

	def convert_bridge_link(self, link):
		""" Given a regular link to the bridge
		    make sure it points to the actual bridge
		"""
		linkparts = urlparse.urlparse(link)
		testparts = urlparse.urlparse(self.args['bridge_uri'])
		url = urlparse.urlunparse((testparts[0], testparts[1], linkparts[2], linkparts[3], linkparts[4], linkparts[5]))
		return url

	def delete_auths(self):
		""" Deletes any authorizations of this client_id in the bridge """
		url = self.args['bridge_uri']
		parsed = urlparse.urlparse(url)
		url = urlparse.urlunparse((parsed[0],parsed[1],'','','client_id='+self.args['client_id'],''))
		r = requests.get(url, verify=False)
		linkre = re.compile('<a\s+href="(.*?delete.*?)"')
		for link in linkre.finditer(r.text):
			link = link.group(1)
			link = self.convert_bridge_link(link)
			resp = requests.get(link, verify=False, allow_redirects=False)

	@staticmethod
	def validate_access(access_token):
		validate_url = 'http://127.0.0.1:9873/validate?access_token=%s'%(urllib.quote(access_token),)
		resp = requests.get(validate_url)
		if int(resp.status_code / 100) == 2:
			return True
		else:
			return False
	@classmethod
	def teardown_class(klass):
		klass.bridge.terminate()
		klass.server.terminate()

	def click_auth(self, url):
		url = self.convert_bridge_link(url)
		r = requests.get(url, verify=False)
		linkre = re.compile('<a\s+href="(.*?try_auth.*?)"')
		match = linkre.search(r.text)
		if match:
			link = match.group(1)
			link = urlparse.urljoin(url, link)
		else:
			print("Could not find try_auth link in page %s:\n%s"%(url,r.text))
		assert_true(match)
		# click on try_auth link
		link = self.convert_bridge_link(link)
		resp = requests.get(link, verify=False, allow_redirects=False)
		# follow redirect from oauth server
		link = resp.headers['Location']
		resp = requests.get(link, verify=False, allow_redirects=False)
		# finish redirect
		link = self.convert_bridge_link(resp.headers['Location'])
		requests.get(link, verify=False, allow_redirects=False)

	def test_create_client(self):
		try:
			c = BridgeClient(self.args['bridge_uri'], self.args['client_id'], self.args['client_secret'], self.args['auth_uri'], self.args['token_uri'], self.args['scope'])
			fail("Didn't crash when getting initial client")
		except NeedsAuthentication as e:
			url = e.location
		self.click_auth(url)
		# should not fail now
		c = BridgeClient(self.args['bridge_uri'], self.args['client_id'], self.args['client_secret'], self.args['auth_uri'], self.args['token_uri'], self.args['scope'])
		assert_true(c.access_token)
		assert_true(self.validate_access(c.access_token))
		r = c.requests.get(self.args['validate_uri'])
		assert_equal(200, r.status_code)

		# refresh new access token
		cur_token = c.access_token
		r = requests.delete('http://localhost:9873/accesstoken',data={'client_id':self.args['client_id']})
		assert_equal(200, r.status_code)
		assert_false(self.validate_access(c.access_token))
		r = c.requests.get(self.args['validate_uri'])	# refreshes
		assert_equal(200, r.status_code)
		assert_true(self.validate_access(c.access_token))
		assert_false(cur_token == c.access_token)

		# delete refresh token
		cur_token = c.access_token
		r = requests.delete('http://localhost:9873/refreshtoken',data={'client_id':self.args['client_id']})
		assert_equal(200, r.status_code)
		assert_true(self.validate_access(c.access_token))
		r = c.requests.get(self.args['validate_uri'])   # be the same
		assert_equal(200, r.status_code)
		assert_true(self.validate_access(c.access_token))
		assert_true(cur_token == c.access_token)

		# delete refresh token
		cur_token = c.access_token
		r = requests.delete('http://localhost:9873/accesstoken',data={'client_id':self.args['client_id']})
		assert_equal(200, r.status_code)
		assert_false(self.validate_access(c.access_token))
		try:
			r = c.requests.get(self.args['validate_uri'])   # be the same
			fail("Should fail")
		except NeedsAuthentication as e:
			url = e.location
		# try to click again
		self.click_auth(url)
		# should not fail now
		c = BridgeClient(self.args['bridge_uri'], self.args['client_id'], self.args['client_secret'], self.args['auth_uri'], self.args['token_uri'], self.args['scope'])
		assert_true(c.access_token)
		assert_true(self.validate_access(c.access_token))
		r = c.requests.get(self.args['validate_uri'])
		assert_equal(200, r.status_code)
