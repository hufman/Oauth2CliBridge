import requests

class RequestsAdapter(object):
	def __init__(self, bridgeclient):
		self.bridgeclient = bridgeclient

	def __getattr__(self, name):
		methods = ['get','post','put','delete','head','options']
		if name in methods:
			return lambda url,*args,**kwargs: self.request(name, url, *args, **kwargs)
		raise AttributeError(name)

	def request(self, method, url, *args, **kwargs):
		call = getattr(requests, method)
		mkwargs = dict(kwargs)
		headers = mkwargs.get('headers', {})
		mkwargs['headers'] = headers
		headers['Authorization'] = 'Bearer '+self.bridgeclient.access_token
		response = call(url, *args, **mkwargs)
		if response.status_code == 401:
			self.bridgeclient.load_access_token()
			headers['Authorization'] = 'Bearer '+self.bridgeclient.access_token
			response = call(url, *args, **mkwargs)
			if response.status_code == 401:
				self.bridgeclient.load_access_token(True)
				headers['Authorization'] = 'Bearer '+self.bridgeclient.access_token
				response = call(url, *args, **mkwargs)
		return response
