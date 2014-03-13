Oauth2CliBridge
===============

This is a small webservice to help commandline applications authenticate to Oauth2 providers. This webservice handles all the Oauth2 protocol and user authentication, giving access tokens to commandline applications that request them.

Overview
--------

Oauth2 is a method for accessing a web service API with certain user-granted permissions. The client requests a specific list of permissions, which the user must accept. The web service then uses the access token to grant access to those specific API calls.
A typical Oauth2 conversation looks like this:

1. The Oauth2 client (aka consumer) pre-registers for a client id and client secret from the Oauth2 server (aka provider)
2. The user visits the Oauth2 client with a web browser and clicks a button such as "Log in with Google" or other Oauth2 provider
3. This button sends the user to the Oauth2 server, along with the client id and a list of requested permissions
4. The Oauth2 server shows a prompt to the user, requesting permissions for the Oauth2 client
5. Upon acceptance, the user is redirected back to the Oauth2 client's webpage, along with an auth code
6. The Oauth2 client, behind the scenes, sends this auth code, the same client id as before, and the client secret to the Oauth2 server
7. The Oauth2 server returns an access code to the Oauth2 client
8. The Oauth2 client sends this access code along with any API requests

However, this requires that the Oauth2 client is web-accessible and that it has an SSL certificate. The Oauth2 client's URL must remain the same, so that the Oauth2 server can redirect the user back to it reliably. These requirements make it difficult for a commandline program to access APIs protected by Oauth2.

Oauth2CliBridge provides a web service that commandline programs can use to obtain Oauth2 access tokens. The commandline program has an Oauth2 client id and client secret, just like a normal Oauth2 client. The commandline program then sends its client id, client secret, and requested permissions to Oauth2CliBridge, which uses them to act as a regular Oauth2 client. After the Oauth2 protocol is done, it gives the access token back to the commandline application, which can then access the API.

The Oauth2CliBridge conversation looks like this:

1. The commandline program pre-registers for an Oauth2 client id and client secret from the Oauth2 server (aka provider)
2. The commandline program sends the location of the Oauth2 server, the client id, and the client secret to the Oauth2CliBridge
3. The user visits the Oauth2CliBridge with a web browser and selects the pending request from the commandline program
4. The user is sent to the Oauth2 server, along with the client id and a list of requested permissions
5. The Oauth2 server shows a prompt to the user, requesting permissions for the Oauth2 client
6. Upon acceptance, the user is redirected back to the Oauth2CliBridge's webpage, along with an auth code
7. The Oauth2CliBridge, behind the scenes, sends this auth code, the same client id as before, and the client secret to the Oauth2 server
8. The Oauth2 server returns an access code to the Oauth2CliBridge
9. The Oauth2CliBridge saves this access code
10. The commandline program requests the access code from the Oauth2CliBridge
11. The commandline program sends this access code along with any API requests

With the access token, the commandline program can access APIs protected by Oauth2. After the access token expires, the commandline program can request a new access token from the Oauth2Cli, with the exact same request as before.

Setup Steps
-----------

1. Set up the bridge to run behind a reverse proxy that supports SSL, because Oauth2 requires that everything is done through SSL
2. Set up a url so that the intended user can get to the https port of the bridge. It doesn't need to be externally accessible
3. Set up oauth2clibridge/server/localsettings.py to have a URL variable that points to your `https://{bridgelink}`
4. You may also want to set up a DATABASE\_URI variable to point to a real database, as opposed to the default memory sqlite instance
5. When registering your Oauth2 application, set `https://{bridgelink}/oauth2callback` as the callback url
6. The server should now be ready, try out running the client with your Oauth2 client credentials

Client Library
--------------

There is a handy class called oauthclibridge.client.BridgeClient that provides a wrapper around Requests to automatically send the access token to APIs.

Instantiate it by passing it your bridge url, client id, client secret, Oauth2 auth uri, Oauth2 token uri, Oauth2 scope string, an optional name, and an optional verify value for the underlying Requests ssl functionality.

Upon instantiation, it will try to connect to the bridge and get an access code. It may throw a NeedsAuthentication exception, with a link to the bridge for the user to complete the Oauth2 protocol. After the user has logged in, run the instantiation again and it should return successfully.

The BridgeClient object has an `access_token` attribute, in case you need direct access to it. Otherwise, you can use BridgeClient.requests.get or BridgeClient.requests.post or any other HTTP method that Request supports. Technically these wrapper methods may also through a NeedsAuthentication exception, but only after the token expires. There is an `expiration` attribute which will give the timestamp for when the token expires.

Look in oauth2client.examples to see examples of how to use the client library

Protocol and Implementation
---------------------------

The protocol with which the client talks to the bridge is modelled after the token POST protocol from Oauth2. To `https://{bridgelink}/token`, POST an urlencoded list of parameters: `client_id`, `client_secret`, `auth_uri`, `token_uri`, `scope`. You can also add a `name` parameter, to have multiple accounts logged in with the same `client_id`. It also accepts a `force_new_access` parameter, which says to delete the current `access_token` and use a stored `refresh_token` to get a new one, or prompt the user to click through again.

An example POST contains data like this: `client_id=MY_CLIENT_ID&client_secret=LONGRANDOMSTRING&auth_uri=https%3A%2F%2Fgithub.com%2Flogin%2Foauth%2Fauthorize&token_uri=https%3A%2F%2Fgithub.com%2Flogin%2Foauth%2Faccess_token&scope=user%2Cread%3Apublic_key&name=me`

The server may return 400 if the request is invalid or if the backend Oauth2 server rejected the request. It returns an HTTP 401 error with a Location header if the user needs to visit the bridge web interface to sign in.

The bridge does not store the `client_secret` anywhere, and it uses the `client_secret` to encrypt the `access_token` and `refresh_token` in the database. Because of this, tokens can not be refreshed in the background, the client library has to initiate the request, sending the `client_secret`, before the bridge can load the `refresh_token` and trade it in for a new `access_token`.
