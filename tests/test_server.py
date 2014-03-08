from nose.tools import *
import time
import thread
import socket
import requests
import urllib
import urlparse
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import sys
sys.path.append('lib/oauth2testserver/')
from oauth2testserver import main as testserver, oauth2 as testserver_store
from stoppable_wsgi import StoppableWSGIServer

from oauth2clibridge.server import handler, models

class TestServerManually:
	@classmethod
	def setup_class(klass):
		klass.server = StoppableWSGIServer(host='127.0.0.1', port=9873)
		args = {'server':klass.server, 'quiet':True}
		klass.oauth2server = thread.start_new_thread(testserver.run, (), args)
		attempts = 20
		while attempts > 0 and not klass.is_ready(('127.0.0.1',9873)):
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
		DATABASE_URI = 'sqlite:///:memory:'
		engine = create_engine(DATABASE_URI)
		models.create_db(engine)
		db = sessionmaker(bind=engine)()
		db.rollback()
		self.handler = handler.Oauth2Handler(db, 'http://bridge:234/callback')

		client_id,client_secret = self.generate_client()
		self.args = self.generate_args(client_id, client_secret)

	@staticmethod
	def generate_client():
		resp = requests.post('http://127.0.0.1:9873/client')
		data = json.loads(resp.text)
		return (data['client_id'], data['client_secret'])

	@staticmethod
	def generate_args(client_id, client_secret):
		args = {'client_id': client_id,
		        'client_secret': client_secret,
		        'auth_uri': 'http://127.0.0.1:9873/auth',
		        'token_uri': 'http://127.0.0.1:9873/token',
		        'scope': 'test'
		}
		return args

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
		klass.server.stop()

	def test_create_unnamed(self):
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(0, len(records))
		ret = self.handler.token(self.args)
		assert_equal(None, ret)
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))

	def test_create_named(self):
		self.args['name'] = 'hi'
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(0, len(records))
		ret = self.handler.token(self.args)
		assert_equal(None, ret)
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))
		assert_equal('hi', records[0].name)

	def test_create_authurl(self):
		ret = self.handler.token(self.args)
		records = self.handler.get_records(self.args['client_id'])
		url = self.handler.make_auth_uri(records[0])
		parsed_url = urlparse.urlparse(url)
		assert_equal('http', parsed_url.scheme)
		assert_equal('127.0.0.1:9873', parsed_url.netloc)
		assert_equal('/auth', parsed_url.path)
		assert_equal('', parsed_url.params)
		assert_equal('', parsed_url.fragment)
		qs = urlparse.parse_qs(parsed_url.query)
		for v in qs.values():
			# only a single element per qs name
			assert_equal(1, len(v))
		qs = dict([(k,v[0]) for k,v in qs.items()])
		assert_in('response_type', qs)
		assert_in('client_id', qs)
		assert_in('redirect_uri', qs)
		assert_in('scope', qs)
		assert_in('state', qs)
		assert_in('access_type', qs)
		assert_in('approval_prompt', qs)
		assert_in('include_granted_scopes', qs)
		assert_equal(qs['response_type'], 'code')
		assert_equal(qs['access_type'], 'offline')
		assert_equal(qs['approval_prompt'], 'force')
		assert_equal(qs['include_granted_scopes'], 'true')
		assert_equal(qs['client_id'], self.args['client_id'])

	def test_create_authcode(self):
		ret = self.handler.token(self.args)
		records = self.handler.get_records(self.args['client_id'])
		url = self.handler.make_auth_uri(records[0])
		parsed_url = urlparse.urlparse(url)
		qs = urlparse.parse_qs(parsed_url.query)
		state = qs['state'][0]

		resp = requests.get(url, allow_redirects=False)
		assert_in('Location', resp.headers)
		parsed_url = urlparse.urlparse(resp.headers['Location'])
		assert_equal('http', parsed_url.scheme)
		assert_equal('bridge:234', parsed_url.netloc)
		assert_equal('/callback', parsed_url.path)
		assert_equal('', parsed_url.params)
		assert_equal('', parsed_url.fragment)
		qs = urlparse.parse_qs(parsed_url.query)
		for v in qs.values():
			# only a single element per qs name
			assert_equal(1, len(v))
		qs = dict([(k,v[0]) for k,v in qs.items()])
		assert_not_in('error', qs)
		assert_in('state', qs)
		assert_in('code', qs)
		assert_equal(qs['state'], state)
		code = qs['code']

		# parse out the oauth2 state and save the code
		parsed_state = urlparse.parse_qs(qs['state'])
		parsed_state = dict([(k,v[0]) for k,v in parsed_state.items()])
		assert_in('id', parsed_state)
		assert_in('csrf', parsed_state)
		id = parsed_state['id']
		csrf = parsed_state['csrf']

		# save the authcode
		self.handler.store_auth_code(id, csrf, code)
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))
		assert_equal(code, records[0].auth_code)

	def load_authcode(self):
		""" Do everything to get the auth code """
		ret = self.handler.token(self.args)
		self.oauth2_authorize()

	def oauth2_authorize(self):
		""" Visits the test oauth2 server, which will then
		    redirect back with auth code
		"""
		# get link to oauth2 server
		records = self.handler.get_records(self.args['client_id'])
		url = self.handler.make_auth_uri(records[0])

		# user authorization
		resp = requests.get(url, allow_redirects=False)
		parsed_url = urlparse.urlparse(resp.headers['Location'])
		qs = urlparse.parse_qs(parsed_url.query)
		parsed_state = urlparse.parse_qs(qs['state'][0])
		code = qs['code'][0]
		id = parsed_state['id'][0]
		csrf = parsed_state['csrf'][0]
		self.auth_code = code
		self.handler.store_auth_code(id, csrf, code)

	def test_create_realcode(self):
		self.load_authcode()

		# trade in auth code
		records = self.handler.get_records(self.args['client_id'])
		record = records[0]
		self.handler.tradein_auth_code(record, self.args['client_secret'])
		assert_equal(self.auth_code, record.auth_code, "Didn't clear auth_code")
		assert_not_equal(None, record.refresh_token, "Has refresh token")
		assert_not_equal(None, record.access_token, "Has access token")
		access_token_data = handler.access_token(record, self.args['client_secret'])
		assert_in('access_token', access_token_data)
		access_token = access_token_data['access_token']
		assert_true(len(access_token) > 10)

		# check access_token
		assert_true(self.validate_access(access_token))

	def test_invalid_client_authcode(self):
		self.load_authcode()

		# delete client
		resp = requests.delete('http://127.0.0.1:9873/client', data=self.args)

		# trade in auth code
		records = self.handler.get_records(self.args['client_id'])
		self.handler.tradein_auth_code(records[0], self.args['client_secret'])
		assert_equal(None, records[0].auth_code, "Cleared auth_code")
		assert_equal(None, records[0].refresh_token, "No refresh token")
		assert_equal(None, records[0].access_token, "No access token")

	def test_missing_authcode(self):
		self.load_authcode()

		# delete client auth code
		requests.delete('http://127.0.0.1:9873/auth', data={'client_id':self.args['client_id']})

		# trade in auth code
		records = self.handler.get_records(self.args['client_id'])
		self.handler.tradein_auth_code(records[0], self.args['client_secret'])
		assert_equal(None, records[0].auth_code, "Cleared auth_code")
		assert_equal(None, records[0].refresh_token, "No refresh token")
		assert_equal(None, records[0].access_token, "No access token")

	def test_invalid_authcode(self):
		self.load_authcode()

		# delete client auth code
		testserver_store.client_auth[self.args['client_id']] = "INVALID!!!"

		# trade in auth code
		records = self.handler.get_records(self.args['client_id'])
		record = records[0]
		self.handler.tradein_auth_code(record, self.args['client_secret'])
		assert_equal(None, record.auth_code, "Cleared auth_code")
		assert_equal(None, record.refresh_token, "No refresh token")
		assert_equal(None, record.access_token, "No access token")

	def test_refresh_code(self):
		self.load_authcode()

		# trade in auth code
		records = self.handler.get_records(self.args['client_id'])
		record = records[0]
		self.handler.tradein_auth_code(record, self.args['client_secret'])
		access_token_data = handler.access_token(record, self.args['client_secret'])
		access_token = access_token_data['access_token']

		assert_true(self.validate_access(access_token))

		# clear out the tokens and try refresh
		record.auth_code = None
		record.access_token = None
		self.handler.refresh_access(record, self.args['client_secret'])

		# try to validate
		assert_equal(None, records[0].auth_code, "Didn't fetch a new auth_code")
		assert_not_equal(None, records[0].refresh_token, "Has refresh token")
		assert_not_equal(None, records[0].access_token, "Has access token")
		access_token_data = handler.access_token(records[0], self.args['client_secret'])
		assert_in('access_token', access_token_data)
		access_token = access_token_data['access_token']
		assert_true(len(access_token) > 10)

		# check access_token
		assert_true(self.validate_access(access_token))

	def test_missing_client_refresh(self):
		self.load_authcode()

		# trade in auth code
		records = self.handler.get_records(self.args['client_id'])
		record = records[0]
		self.handler.tradein_auth_code(record, self.args['client_secret'])
		access_token_data = handler.access_token(record, self.args['client_secret'])
		access_token = access_token_data['access_token']

		assert_true(self.validate_access(access_token))

		# invalidate client
		requests.delete('http://127.0.0.1:9873/refreshtoken', data={'client_id':self.args['client_id']})

		# clear out the tokens and try refresh
		record.auth_code = None
		record.access_token = None
		self.handler.refresh_access(record, self.args['client_secret'])

		# Make sure we didn't get a token
		assert_equal(None, record.auth_code, "No auth code")
		assert_equal(None, record.refresh_token, "No refresh token")
		assert_equal(None, record.access_token, "No access token")

	def test_invalid_client_refresh(self):
		self.load_authcode()

		# trade in auth code
		records = self.handler.get_records(self.args['client_id'])
		record = records[0]
		self.handler.tradein_auth_code(record, self.args['client_secret'])
		access_token_data = handler.access_token(record, self.args['client_secret'])
		access_token = access_token_data['access_token']

		assert_true(self.validate_access(access_token))

		# invalidate client
		testserver_store.client_refresh[self.args['client_id']] = "INVALID!!!"

		# clear out the tokens and try refresh
		record.auth_code = None
		record.access_token = None
		self.handler.refresh_access(record, self.args['client_secret'])

		# Make sure we didn't get a token
		assert_equal(None, record.auth_code, "No auth code")
		assert_equal(None, record.refresh_token, "No refresh token")
		assert_equal(None, record.access_token, "No access token")

	def test_token_flow(self):
		self.handler.token(self.args)	# creates record
		self.oauth2_authorize()		# user authorization
		self.handler.token(self.args)	# should tradein auth code

		# check status
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))
		record = records[0]
		# has all the tokens
		assert_not_equal(None, record.auth_code)
		assert_not_equal(None, record.refresh_token)
		assert_not_equal(None, record.access_token)
		# access token works
		access_token_data = handler.access_token(record, self.args['client_secret'])
		access_token = access_token_data['access_token']
		assert_true(self.validate_access(access_token))

	def test_token_flow_repeat(self):
		self.handler.token(self.args)	# creates record
		self.oauth2_authorize()		# user authorization
		self.handler.token(self.args)	# should tradein auth code

		# check status
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))
		record = records[0]
		# has all the tokens
		assert_not_equal(None, record.auth_code)
		assert_not_equal(None, record.refresh_token)
		assert_not_equal(None, record.access_token)
		# access token works
		access_token_data = handler.access_token(record, self.args['client_secret'])
		access_token = access_token_data['access_token']
		assert_true(self.validate_access(access_token))

		# get it again
		self.handler.token(self.args)	# should tradein auth code
		# check status
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))
		record = records[0]
		# has all the tokens
		assert_not_equal(None, record.auth_code)
		assert_not_equal(None, record.refresh_token)
		assert_not_equal(None, record.access_token)
		# access token works
		access_token_data2 = handler.access_token(record, self.args['client_secret'])
		access_token2 = access_token_data2['access_token']
		assert_equal(access_token, access_token2)
		assert_true(self.validate_access(access_token2))


	def test_token_missing_expiration(self):
		self.handler.token(self.args)	# creates record
		self.oauth2_authorize()		# user authorization
		self.handler.token(self.args)	# should tradein auth code
		record = self.handler.get_records(self.args['client_id'])[0]
		record.access_exp = None	# pretend we never got one
		self.handler.token(self.args)	# should use the same one

		# check status
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))
		record = records[0]
		# has all the tokens
		assert_not_equal(None, record.auth_code)
		assert_not_equal(None, record.refresh_token)
		assert_not_equal(None, record.access_token)
		# access token works
		access_token_data = handler.access_token(record, self.args['client_secret'])
		access_token = access_token_data['access_token']
		assert_true(self.validate_access(access_token))

	def test_token_force_refresh(self):
		self.handler.token(self.args)	# creates record
		self.oauth2_authorize()		# user authorization
		self.handler.token(self.args)	# should tradein auth code

		# check status
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))
		record = records[0]
		# has all the tokens
		assert_not_equal(None, record.auth_code)
		assert_not_equal(None, record.refresh_token)
		assert_not_equal(None, record.access_token)
		# access token works
		access_token_data = handler.access_token(record, self.args['client_secret'])
		access_token = access_token_data['access_token']
		assert_true(self.validate_access(access_token))
		# try getting access token again
		self.handler.token(self.args)	# should get previous access
		access_token_data = handler.access_token(record, self.args['client_secret'])
		assert_equal(access_token, access_token_data['access_token'])
		# try getting access token again
		self.args['force_new_access'] = True
		self.handler.token(self.args)	# should get previous access
		access_token_data = handler.access_token(record, self.args['client_secret'])
		assert_not_equal(access_token, access_token_data['access_token'])
		# try getting access token again without refresh
		requests.delete('http://127.0.0.1:9873/refreshtoken', data={'client_id':self.args['client_id']})
		self.handler.token(self.args)	# should await user input
		assert_equal(None, record.auth_code)
		assert_equal(None, record.refresh_token)
		assert_equal(None, record.access_token)

	def test_token_flow_invalid_client(self):
		self.handler.token(self.args)	# creates record
		self.oauth2_authorize()		# user authorization
		resp = requests.delete('http://127.0.0.1:9873/client', data=self.args)
		self.handler.token(self.args)	# should zero out auth code

		# check status
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))
		record = records[0]
		# has all the tokens
		assert_equal(None, record.auth_code)
		assert_equal(None, record.refresh_token)
		assert_equal(None, record.access_token)

	def test_token_flow_missing_authcode(self):
		self.handler.token(self.args)	# creates record
		self.oauth2_authorize()		# user authorization
		requests.delete('http://127.0.0.1:9873/auth', data={'client_id':self.args['client_id']})
		self.handler.token(self.args)	# should zero out auth code

		# check status
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))
		record = records[0]
		# has all the tokens
		assert_equal(None, record.auth_code)
		assert_equal(None, record.refresh_token)
		assert_equal(None, record.access_token)

	def test_token_flow_invalid_authcode(self):
		self.handler.token(self.args)	# creates record
		self.oauth2_authorize()		# user authorization
		testserver_store.client_auth[self.args['client_id']] = "INVALID!!!"
		self.handler.token(self.args)	# should zero out auth code

		# check status
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))
		record = records[0]
		# has all the tokens
		assert_equal(None, record.auth_code)
		assert_equal(None, record.refresh_token)

	def test_token_flow_refresh(self):
		self.handler.token(self.args)	# creates record
		self.oauth2_authorize()		# user authorization
		self.handler.token(self.args)	# should tradein auth code
		record = self.handler.get_records(self.args['client_id'])[0]
		record.auth_code = None
		record.access_token = None
		self.handler.token(self.args)	# should tradein refresh code

		# check status
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))
		record = records[0]
		# has all the tokens
		assert_equal(None, record.auth_code)
		assert_not_equal(None, record.refresh_token)
		assert_not_equal(None, record.access_token)
		# access token works
		access_token_data = handler.access_token(record, self.args['client_secret'])
		access_token = access_token_data['access_token']
		assert_true(self.validate_access(access_token))

	def test_token_flow_missing_refresh(self):
		self.handler.token(self.args)	# creates record
		self.oauth2_authorize()		# user authorization
		self.handler.token(self.args)	# gets refresh and access tokens
		requests.delete('http://127.0.0.1:9873/refreshtoken', data={'client_id':self.args['client_id']})
		record = self.handler.get_records(self.args['client_id'])[0]
		record.access_token = None
		# auth code has already been deleted, make a new one
		self.oauth2_authorize()		# user authorization
		self.handler.token(self.args)	# should try refresh code, fail and use auth

		# check status
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))
		record = records[0]
		# has all the tokens
		assert_not_equal(None, record.auth_code)
		assert_not_equal(None, record.refresh_token)
		assert_not_equal(None, record.access_token)
		access_token_data = handler.access_token(record, self.args['client_secret'])
		access_token = access_token_data['access_token']
		assert_true(self.validate_access(access_token))

	def test_token_flow_missing_auth_and_refresh(self):
		self.handler.token(self.args)	# creates record
		self.oauth2_authorize()		# user authorization
		self.handler.token(self.args)	# gets refresh and access tokens
		requests.delete('http://127.0.0.1:9873/refreshtoken', data={'client_id':self.args['client_id']})
		record = self.handler.get_records(self.args['client_id'])[0]
		record.access_token = None
		record.auth_token = None
		self.handler.token(self.args)	# should fail refresh and auth

		# check status
		records = self.handler.get_records(self.args['client_id'])
		assert_equal(1, len(records))
		record = records[0]
		# has no the tokens
		assert_equal(None, record.auth_code)
		assert_equal(None, record.refresh_token)
		assert_equal(None, record.access_token)
