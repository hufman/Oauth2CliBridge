#!/usr/bin/env pythonn

import requests
import time
import string
import random
import urllib
import urlparse

import sys
from os.path import dirname, join
sys.path.insert(0, join(dirname(__file__), '..', '..'))

from oauth2clibridge.server.models import Oauth2Record
from oauth2clibridge.server.encryption import encrypt, decrypt, hash_sha1_64

import logging
logger = logging	# default until main overrides

class FailedToTradein(Exception):
	def __init__(self, message):
		self.message = message

# Utility functions
def get_token(size=24):
	choices = string.ascii_letters + string.digits
	return ''.join([random.choice(choices) for i in xrange(size)])

def results_by_matching_scope(results, scope):
	good_results = []
	comma_splitted = scope.split(',')
	space_splitted = scope.split()
	if len(comma_splitted) > len(space_splitted):
		query_scopes = comma_splitted
	else:
		query_scopes = space_splitted
	query_scopes = [x.strip() for x in query_scopes]
	for result in results:
		comma_splitted = result.scope.split(',')
		space_splitted = result.scope.split()
		if len(comma_splitted) > len(space_splitted):
			result_scopes = comma_splitted
		else:
			result_scopes = space_splitted
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
				logger.debug("Invalidated %s because of invalid access checksum"%(result.id,))
				other_results.append(result)
			else:
				# check token expiration
				if result.access_exp and \
				   result.access_exp - time.time() < 300:
					# will expire in less than 5 minutes
					logger.debug("Invalidated %s because it will expire in less than 5 minutes: %s"%(result.id,result.access_exp - time.time()))
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
	""" Loads up an access_token from the database
	    The resulting object can be returned to the client
	"""
	access_token = decrypt(client_secret, record.access_token)
	if hash_sha1_64(access_token) == record.access_sha1:
		token = {
		    "access_token": access_token,
		    "token_type": record.access_token_type
		}
		if record.access_exp:
			token['expires_in'] = int(record.access_exp - time.time())
		else:
			token['expires_in'] = 600	# 10 minute default
		return token
	else:
		logger.info("Invalid access checksum in database")
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
		r = requests.post(record.token_uri, data=data)
		record.auth_code = None
		if int(r.status_code / 100) == 2:
			logger.debug("Received access info for %s"%(record.client_id,))
			try:
				token_data = r.json()
			except ValueError as e:
				token_data = urlparse.parse_qs(r.text)
				token_data = dict([(k,v[0]) for k,v in token_data.items()])
		else:
			token_data = None
		if token_data is not None and 'error' not in token_data:
			self.parse_access_token(record, client_secret, token_data)
		else:
			logger.warning("Errored response for access info for %s:\n%s"%(record.client_id,r.text))
			record.refresh_token = None
			record.refresh_sha1 = None
			record.access_token = None
			record.access_sha1 = None
			record.access_exp = None
			self.db.commit()
			return FailedToTradein(r.text)
		self.db.commit()
		return record

	def parse_access_token(self, record, client_secret, token_data):
		logger.info("Received access token for "+record.client_id)
		record.access_token = encrypt(client_secret, token_data['access_token'])
		record.access_sha1 = hash_sha1_64(token_data['access_token'])
		if 'expires_in' in token_data:		# required per spec
			record.access_exp = time.time() + int(token_data['expires_in'])
		elif 'expires' in token_data:		# facebook is wrong
			record.access_exp = time.time() + int(token_data['expires'])
		else:
			logger.debug("Strange, access token is missing expiration")
		if 'token_type' in token_data:		# required per spec
			record.access_token_type = token_data['token_type']
		else:
			logger.debug("Access token is missing token_type, assuming Bearer")
			record.access_token_type = 'Bearer'
		if urlparse.urlparse(record.token_uri).netloc == 'graph.facebook.com':
			self.parse_facebook_token(record, client_secret, token_data)
		self.db.commit()
		if 'refresh_token' in token_data:
			self.parse_refresh_token(record, client_secret, token_data)

	def parse_refresh_token(self, record, client_secret, token_data):
		if 'refresh_token' in token_data:
			logger.info("Received refresh token for "+record.client_id)
			record.refresh_token = encrypt(client_secret, token_data['refresh_token'])
			record.refresh_sha1 = hash_sha1_64(token_data['refresh_token'])
			self.db.commit()

	def parse_facebook_token(self, record, client_secret, token_data):
		access = token_data['access_token']
		params = {'input_token':access, 'access_token':access}
		resp = requests.get('https://graph.facebook.com/debug_token', params=params)
		if resp.status_code == 200 and \
		   'data' in resp.json():
			if 'issued_at' not in resp.json()['data']:
				# received short token, get a long one
				params = {'grant_type':'fb_exchange_token',
					  'client_id':record.client_id,
					  'client_secret':client_secret,
					  'fb_exchange_token':access}
				resp = requests.get('https://graph.facebook.com/oauth/access_token', params=params)
				token_data = urlparse.parse_qs(rres.text)
				token_data = dict([(k,v[0]) for k,v in token_data.items()])
				if token_data is not None and 'error' not in token_data:
					logger.info("Traded up to long-lived FB token for "+client_id)
					self.parse_access_token(record, client_secret, token_data)
				else:
					record.refresh_token = None
					record.refresh_sha1 = None
					record.access_token = None
					record.access_sha1 = None
					record.access_exp = None
			else:
				# already have long-lived token
				logger.info("Already have long-lived FB token for "+record.client_id)
				pass
		else:
			# error while loading page
			logger.warning('Failed to load info about Facebook token:\n'+resp.text())

	def get_records(self, client_id):
		query = self.db.query(Oauth2Record)
		if client_id:
			query = query.filter(Oauth2Record.client_id == client_id)
			results = [x for x in query]
		else:
			results = []
		return results

	def get_record(self, id, csrf):
		query = self.db.query(Oauth2Record)
		query = query.filter(Oauth2Record.id==id)
		query = query.filter(Oauth2Record.csrf==csrf)
		return query.first()

	def delete_record(self, record):
		self.db.delete(record)
		self.db.commit()

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
			forced = args.get('force_new_access','False')
			forced = forced.lower() not in ['0','false','no','none']
			if data != None and not forced:
				logger.info("Found valid access token for "+client_id)
				return data
			else:
				if data == None:
					logger.debug("Found invalid access token for "+client_id)
				elif forced:
					logger.debug("Forced refresh from "+client_id)
				else:
					logger.debug("Unusual access circumstances from "+client_id)
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
		failure = None
		for result in auth_results:
			ret = self.tradein_auth_code(result, client_secret)
			if isinstance(ret, FailedToTradein):
				failure = ret	# save in case others don't work
			if result.access_token is None:		# failed to refresh
				good_results.append(result)
			else:
				data = access_token(result, client_secret)
				if data != None:
					logger.info("Found valid auth token for "+client_id)
					return data
				else:
					good_results.append(result)
		if failure:
			return failure.message, 400

		if len(good_results) == 0:	# create a request for this
			logger.info("Created request for "+client_id)
			record = Oauth2Record(
			    client_id=client_id, name=args.get('name'),
			    auth_uri=args['auth_uri'], token_uri=args['token_uri'],
			    csrf=get_token(), scope=args['scope'])
			record.scope = args['scope']
			self.db.add(record)
			self.db.commit()
		else:			# found a request, but couldn't use it
			if any([x.access_token != None for x in good_results]):
				return "Existing Oauth2 connections could not be used, check client_secret", 400
		return None

