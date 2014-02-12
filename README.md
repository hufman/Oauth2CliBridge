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
