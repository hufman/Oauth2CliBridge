#!/usr/bin/env pythonn

from flask import Flask, request, session, g, abort, jsonify, redirect, render_template, url_for
from sqlalchemy import create_engine, sql
from sqlalchemy.orm import sessionmaker, scoped_session
from jinja2 import Markup
import urllib
import urlparse

import os
import sys
from os.path import dirname, join
sys.path.insert(0, join(dirname(__file__), '..', '..'))

import oauth2clibridge.server.models as models
import oauth2clibridge.server.handler as handler
from oauth2clibridge.server.handler import Oauth2Handler

app = Flask(__name__)
app.config.from_pyfile('settings.py')
try:
	app.config.from_pyfile('localsettings.py')
except:
	pass
if 'DEBUG' in os.environ:
	app.config['DEBUG'] = True if os.environ['DEBUG'] in ['True','true'] else False
handler.logger = app.logger

# Database interactions
DEBUG_DB = False
engine = create_engine(app.config['DATABASE_URI'], echo=DEBUG_DB)
db_session = scoped_session(sessionmaker(bind=engine))

def create_db():
	models.create_db(engine)
create_db()

@app.teardown_appcontext
def close_db(error):
	db_session.remove()

@app.before_request
def create_oauth2():
	request.oauth2 = Oauth2Handler(db_session, abs_url_for('callback'))

# Views
@app.route('/')
def main():
	if 'client_id' in request.form:
		client_id = request.form['client_id']
	elif 'client_id' in request.args:
		client_id= request.args['client_id']
	else:
		client_id = None
	results = request.oauth2.get_records(client_id)
	return render_template('main.djhtml', oauth2=results)

@app.route("/try_auth/<int:id>")
def try_auth(id):
	if not 'csrf' in request.args:
		return "Missing csrf argument", 401
	result = request.oauth2.get_record(id,request.args['csrf'])
	if result == None:
		return "Invalid id or csrf", 401
	return redirect(request.oauth2.make_auth_uri(result))
@app.route("/delete/<int:id>")
def delete(id):
	if not 'csrf' in request.args:
		return "Missing csrf argument", 401
	result = request.oauth2.get_record(id,request.args['csrf'])
	if result == None:
		return "Invalid id or csrf", 401
	client_id = result.client_id
	request.oauth2.delete_record(result)
	return redirect(abs_url_for('main', client_id=client_id))

@app.route('/oauth2callback')
def callback():
	state = urlparse.parse_qs(request.args['state'])
	state = dict([(k,v[0]) for (k,v) in state.items()])
	result = request.oauth2.store_auth_code(int(state['id']), state['csrf'], request.args['code'])
	if result:
		headers = {"Location": abs_url_for("main", client_id=state.get('client_id'))}
		return "Successfully authenticated "+state.get('client_id'), 303, headers
	else:
		return "Could not find matching client_id request"

@app.route('/token', methods=['POST'])
def token():
	ret = request.oauth2.token(request.form)
	if ret == None:		# new token session is ready
		url = abs_url_for('main', client_id=request.form['client_id'])
		return "Please visit %s"%(url,), 401, {'Location':url}
	if isinstance(ret, tuple):	# some sort of other error
		return ret
	return jsonify(ret)		# proper token

# Template stuff
def abs_url_for(name, *args, **kwargs):
	url = url_for(name, *args, **kwargs)
	return urlparse.urljoin(app.config['URL'], url)
@app.template_filter('authorized_oauth2')
def filter_authorized(s):
	return [x for x in s if x.auth_code is not None]
@app.template_filter('unauthorized_oauth2')
def filter_unauthorized(s):
	return [x for x in s if x.auth_code is None]
@app.template_filter('not_blank')
def filter_not_blank(s):
	if s is None:
		return ''
	return s
@app.template_filter('cmd_try_auth')
def filter_try_auth(s):
	return Markup(url_for("try_auth", id=int(s.id), csrf=s.csrf))
@app.template_filter('cmd_delete')
def filter_delete(s):
	return Markup(url_for("delete", id=int(s.id), csrf=s.csrf))

if __name__ == '__main__':
	app.run(host='0.0.0.0')
