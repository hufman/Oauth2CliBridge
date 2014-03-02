#!/usr/bin/env pythonn

import requests
import time
import string
import random
import urllib

import sys
from os.path import dirname, join
sys.path.insert(0, join(dirname(__file__), '..', '..'))

from oauth2clibridge.server.models import Oauth2Record
from oauth2clibridge.server.encryption import encrypt, decrypt, hash_sha1_64

import logging
logger = logging	# default until main overrides

# Utility functions
def get_token(size=24):
	choices = string.ascii_letters + string.digits
	return ''.join([random.choice(choices) for i in xrange(size)])

def results_by_matching_scope(results, scope):
	good_results = []
	query_scopes = scope.split(',')
	query_scopes = [x.strip() for x in query_scopes]
	for result in results:
		result_scopes = result.scope.split(',')
		result_scopes = [x.strip() for x in result_scopes]
		diff = set(query_scopes) - set(result_scopes)
		if len(diff) == 0:	# this result has all of the scopes
			good_results.append(result)
	return good_results

def results_by_access_token(results, client_secret):
	""" Splits results by access token validity
	    The first list of results have valid access tokens
	    The second list do not
	"""
	access_results = []
	other_results = []
	for result in results:
		# do we even have a token
		if result.access_token is None:
			other_results.append(result)
		else:
			# check encrypted access token
			tok = result.access_token
			decrypted = decrypt(client_secret, tok)
			if hash_sha1_64(decrypted) != result.access_sha1:
				other_results.append(result)
			else:
				# check token expiration
				if result.access_exp - time.time() < 300:
					# will expire in less than 5 minutes
					other_results.append(result)
				else:
					access_results.append(result)
	return access_results, other_results

def results_by_refresh_token(results, client_secret):
	""" Splits results by refresh token validity
	    The first list of results have valid refresh tokens
	    The second list do not
	"""
	refresh_results = []
	other_results = []
	for result in results:
		# do we even have a token
		if result.refresh_token is None:
			other_results.append(result)
		else:
			# check encrypted refresh token
			tok = result.refresh_token
			decrypted = decrypt(client_secret, tok)
			if hash_sha1_64(decrypted) != result.refresh_sha1:
				other_results.append(result)
			else:
				refresh_results.append(result)
	return refresh_results, other_results

def results_by_auth_code(results):
	""" Splits results by auth token validity
	    The first list of results have valid auth tokens
	    The second list do not
	"""
	auth_results = []
	other_results = []
	for result in results:
		# do we even have a token
		if result.auth_code is None:
			other_results.append(result)
		else:
			auth_results.append(result)
	return auth_results, other_results

def access_token(record, client_secret):
	access_token = decrypt(client_secret, record.access_token)
	if hash_sha1_64(access_token) == record.access_sha1:
		return {
		    "access_token": access_token,
		    "expires_in": int(record.access_exp - time.time()),
		    "token_type": record.access_token_type
		}
	else:
		return None

# Oauth2 request handling
class Oauth2Handler():
	def __init__(self, db_session, callback_uri):
		self.db = db_session
		self.callback_uri = callback_uri

	def make_auth_uri(self, record):
		redirect_uri = self.callback_uri
		state = {"id":record.id, "client_id":record.client_id, "csrf":record.csrf}
		state = urllib.urlencode(state)

		params = {"response_type": "code",
			  "client_id": record.client_id,
			  "redirect_uri": redirect_uri,
			  "scope": record.scope,
			  "state": state,
			  "access_type": "offline",
			  "approval_prompt": "force",
			  "include_granted_scopes": "true"
		}
		return "%s?%s"%(record.auth_uri, urllib.urlencode(params))

	def refresh_access(self, record, client_secret):
		logger.info("Refreshing access token for "+record.client_id)
		refresh_token = decrypt(client_secret, record.refresh_token)
		data = {"client_id": record.client_id, "client_secret": client_secret, \
			"refresh_token": refresh_token, "grant_type": "refresh_token"}
		r = requests.post(record.token_uri, data=data)
		if int(r.status_code / 100) == 2:
			token_data = r.json()
		else:
			token_data = None
		if token_data is not None and 'error' not in token_data:
			self.parse_access_token(record, client_secret, token_data)
		else:
			record.refresh_token = None
			record.refresh_sha1 = None
			record.access_token = None
			record.access_sha1 = None
			record.access_exp = None
			self.db.commit()
		return record

	def tradein_auth_code(self, record, client_secret):
		logger.info("Trading in auth code for "+record.client_id)
		redirect_uri = self.callback_uri
		data = {"client_id": record.client_id, "client_secret": client_secret, \
			"redirect_uri": redirect_uri, \
			"code": record.auth_code, "grant_type": "authorization_code"}
		logger.debug("Auth code info: %s"%(data,))
		r = requests.post(record.token_uri, data=data)
		if int(r.status_code / 100) == 2:
			token_data = r.json()
		else:
			token_data = None
		if token_data is not None and 'error' not in token_data:
			self.parse_access_token(record, client_secret, token_data)
		else:
			record.auth_code = None
			record.refresh_token = None
			record.refresh_sha1 = None
			record.access_token = None
			record.access_sha1 = None
			record.access_exp = None
		self.db.commit()
		return record

	def parse_access_token(self, record, client_secret, token_data):
		logger.info("Received access token for "+record.client_id)
		record.access_token = encrypt(client_secret, token_data['access_token'])
		record.access_sha1 = hash_sha1_64(token_data['access_token'])
		record.access_exp = time.time() + token_data['expires_in']
		record.access_token_type = token_data['token_type']
		self.db.commit()
		if 'refresh_token' in token_data:
			self.parse_refresh_token(record, client_secret, token_data)

	def parse_refresh_token(self, record, client_secret, token_data):
		if 'refresh_token' in token_data:
			logger.info("Received refresh token for "+record.client_id)
			record.refresh_token = encrypt(client_secret, token_data['refresh_token'])
			record.refresh_sha1 = hash_sha1_64(token_data['refresh_token'])
			self.db.commit()

	def get_records(self, client_id):
		query = self.db.query(Oauth2Record)
		results = [x for x in query]
		return results

	def get_record(self, id, csrf):
		query = self.db.query(Oauth2Record)
		query = query.filter(Oauth2Record.id==id)
		query = query.filter(Oauth2Record.csrf==csrf)
		return query.first()

	def store_auth_code(self, id, csrf, auth_code):
		query = self.db.query(Oauth2Record)
		query = query.filter(Oauth2Record.id==id)
		query = query.filter(Oauth2Record.csrf==csrf)
		result = query.first()
		if result:
			result.auth_code = auth_code
			self.db.commit()
			return True
		else:
			return False

	def token(self, args):
		""" Try to log in with the given client_id
		    Returns a access-token dict or None
		"""
		required = ['client_id', 'client_secret', \
			    'auth_uri', 'token_uri', 'scope']
		missing = set(required) - set(args.keys())
		if len(missing) > 0:
			return "Missing post keys: %s"%(', '.join(missing)), 400

		client_id = args['client_id']
		client_secret = args['client_secret']

		# load up the oauth2 records that match this request
		query = self.db.query(Oauth2Record). \
		    filter(Oauth2Record.client_id==client_id). \
		    filter(Oauth2Record.auth_uri==args['auth_uri']). \
		    filter(Oauth2Record.token_uri==args['token_uri']). \
		    filter(Oauth2Record.name==args.get('name'))
		good_results = results_by_matching_scope(query, args['scope'])

		# handle the records
		ready_results, good_results = results_by_access_token(good_results, client_secret)
		for result in ready_results:
			data = access_token(result, client_secret)
			if data != None and not args.get('force_new_access',False):
				logger.info("Found valid access token for "+client_id)
				return data
			else:
				good_results.append(result)

		# refresh any tokens if we can
		refresh_results, good_results = results_by_refresh_token(good_results, client_secret)
		for result in refresh_results:
			logger.info("Trying to refresh token for "+client_id)
			self.refresh_access(result, client_secret)
			if result.access_token is None:		# failed to refresh
				good_results.append(result)
			else:
				data = access_token(result, client_secret)
				if data != None:
					logger.info("Found valid refresh token for "+client_id)
					return data
				else:
					good_results.append(result)

		# use any auth codes to get access and refresh codes
		auth_results, good_results = results_by_auth_code(good_results)
		for result in auth_results:
			self.tradein_auth_code(result, client_secret)
			if result.access_token is None:		# failed to refresh
				good_results.append(result)
			else:
				data = access_token(result, client_secret)
				if data != None:
					logger.info("Found valid auth token for "+client_id)
					return data
				else:
					good_results.append(result)

		if len(good_results) == 0:	# create a request for this
			logger.info("Created request for "+client_id)
			record = Oauth2Record(
			    client_id=client_id, name=args.get('name'),
			    auth_uri=args['auth_uri'], token_uri=args['token_uri'],
			    csrf=get_token(), scope=args['scope'])
			record.scope = args['scope']
			self.db.add(record)
			self.db.commit()
		return None

