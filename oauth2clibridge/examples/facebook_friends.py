#!/usr/bin/env python
import os
from oauth2clibridge.client import BridgeClient, NeedsAuthentication

def load_facebook_data(client, url):
	data = {}
	while url:
		response = client.requests.get(url)
		jresponse = response.json()
		for item in jresponse['data']:
			data[item['id']] = item
		if 'paging' in jresponse and 'next' in jresponse['paging']:
			url = jresponse['paging']['next']
		else:
			url = None
	return data

print("This utility demonstrates the ability to fetch a Facebook user's friend list from the commandline.")
print("It uses the Oauth2CliBridge server to obtain a Facebook API access token.")
print("Please register for a Facebook App key and secret from https://developers.facebook.com")
print('')
print("Please enter the url to your Oauth2CliBridge: ")
clibridge = raw_input()
print("Please enter your Facebook App ID: ")
appid = raw_input()
print("Please enter your Facebook App Secret: ")
appsecret = raw_input()

verify = None
if os.path.isfile('/etc/ssl/certs/ca-certificates.crt'):
	verify = '/etc/ssl/certs/ca-certificates.crt'
client = None
while client == None:
	try:
		client = BridgeClient(clibridge, appid, appsecret,
		                      'https://www.facebook.com/dialog/oauth',
		                      'https://graph.facebook.com/oauth/access_token',
		                      'read_friendlists', verify=verify)
	except NeedsAuthentication as e:
		print("Please visit %s and authorize this application"%(e.location,))
		print("Press enter to continue when ready")
		pause = raw_input()

print("Loading friendlist")
friends = load_facebook_data(client, 'https://graph.facebook.com/me/friends')

print("Loading friend groups")
friendlists = load_facebook_data(client, 'https://graph.facebook.com/me/friendlists')

for group in friendlists.values():
	members = load_facebook_data(client, 'https://graph.facebook.com/%s/members'%(group['id'],))
	for member in members.values():
		if member['id'] in friends:
			buddy = friends[member['id']]
			groups = buddy.get('groups', {})
			groups[group['id']] = group
			buddy['groups'] = groups

for friend in sorted(friends.values(), key=lambda x:x['name']):
	groups_output = ', '.join([x['list_type']+':'+x['name'] for x in friend.get('groups',{}).values()])
	print("%s: %s"%(friend['name'], groups_output))
