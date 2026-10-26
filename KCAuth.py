import time, getpass, requests, os.path, json, sys, secrets, urllib.parse, webbrowser, hmac, hashlib, base64
from http.server import BaseHTTPRequestHandler, HTTPServer

#Note that token settings (access token life time or refresh token sessions) can be changed in realm configuration 

class KCAuth:

    #Attemps to reads from the datastore a valid access token, 
    #If the access token is not valid anymore, it uses the refresh token to attempt to get a new one
    #If the refresh token is not valid anymore, the datastore is deleted and the user must re-enter its credential
    def getAccessTokenFromDatastoreOrRefresh(self):
        if (os.path.isfile(self.datastore_filename)):
            with open(self.datastore_filename, 'r') as f:
                datastore = json.load(f)
                expirationTime = int(datastore["expiration_time"])
                #If the current time is at least 10 seconds above the expiration, return the current access token
                if(expirationTime > int(time.time() + 10)):
                    print("Re-use access token found in datastore " + self.datastore_filename + ", valid till " + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expirationTime)) + " (" + str(expirationTime) + ")" )
                    return datastore["access_token"]
                else:
                    return self.requestAccessTokenBasedOnRefreshToken(datastore)
        else:
            return None

    #Gets an access token based on the refresh token 
    #If an error occurs the datastore is deleted
    #TODO should be called only if refresh token expiration time is still valid
    def requestAccessTokenBasedOnRefreshToken(self, datastore) : 
        print("Using refresh token to get a new access token (refresh token is valid for " + str(int(datastore["refresh_expires_in"]) / 60) + " minutes)")
        refresh_token = datastore["refresh_token"]
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id
        }

        r = requests.post(self.getOrRequestTokenEndPoint(), **self.buildTokenRequestKwargs(payload))
        if (r.status_code != 200):
            print("Some error occured, http code: " + str(r.status_code))
            print(r.text)
            print("ERROR exiting and deleting " + self.datastore_filename + " file.")
            os.remove(self.datastore_filename)
            print("Try again (the datastore file was deleted) and user credentials will be asked again")
            sys.exit(1)
        else:
            return self.saveTokensAndGetAccessToken(r)

    #Gets an access token based on user credentials (when no datastore found)
    #Opens the browser on the authorization endpoint, then starts a local HTTP
    #server to wait for the callback, captures the authorization code and
    #exchanges it for an access/refresh token.
    def requestAccessTokenBasedOnUserCredentials(self) :
        print("No refresh_token found on datastore (" + self.datastore_filename + "), therefore user credentials will be prompted")

        authorization_endpoint = self.getOrRequestAuthorizationEndPoint()
        print("Opening the browser with url="+authorization_endpoint+". Please log in; waiting for the callback on " + self.redirect_uri + " ...")
        webbrowser.open(authorization_endpoint)

        code = self.waitForCallbackCode()
        return self.requestAccessTokenBasedOnAuthorizationCode(code)


    #Starts a local HTTP server on the redirect host/port, waits for a single
    #request on the callback path, validates the 'state' and returns the 'code'.
    def waitForCallbackCode(self):
        expected_state = self.state
        callback_path = urllib.parse.urlparse(self.redirect_uri).path
        # Mutable container so the request handler can hand values back to us
        result = {"code": None, "error": None}

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(handler):
                parsed = urllib.parse.urlparse(handler.path)
                if parsed.path != callback_path:
                    handler.send_response(404)
                    handler.end_headers()
                    return

                params = urllib.parse.parse_qs(parsed.query)

                if "error" in params:
                    result["error"] = params.get("error_description", params["error"])[0]
                elif "state" not in params or params["state"][0] != expected_state:
                    result["error"] = "State mismatch, possible CSRF. Aborting."
                elif "code" not in params:
                    result["error"] = "No authorization code found in callback."
                else:
                    result["code"] = params["code"][0]

                handler.send_response(200)
                handler.send_header("Content-Type", "text/html; charset=utf-8")
                handler.end_headers()
                if result["error"]:
                    body = "<html><body><h2>Authentication failed</h2><p>" + result["error"] + "</p><p>You can close this window.</p></body></html>"
                else:
                    body = "<html><body><h2>Authentication successful</h2><p>You can close this window and return to the console.</p></body></html>"
                handler.wfile.write(body.encode("utf-8"))

            #Silence the default per-request logging to stderr
            def log_message(handler, format, *args):
                return

        host = self.redirect_host
        port = self.redirect_port
        httpd = HTTPServer((host, port), CallbackHandler)
        print("Waiting for callback on http://" + host + ":" + str(port) + callback_path + " ...")
        # handle_request blocks until exactly one request is served
        httpd.handle_request()
        httpd.server_close()

        if result["error"]:
            print("ERROR during authentication callback: " + result["error"])
            sys.exit(1)
        if result["code"] is None:
            print("ERROR: no authorization code received from callback.")
            sys.exit(1)

        print("Authorization code received, exchanging it for a token.")
        return result["code"]


    #Exchanges an authorization code for tokens at the token endpoint
    #Redirect_uri is used for validation by Keycloak (OAuth2 protocol), the URI
    #is not called in this step.
    def requestAccessTokenBasedOnAuthorizationCode(self, code):
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri
        }

        r = requests.post(self.getOrRequestTokenEndPoint(), **self.buildTokenRequestKwargs(payload))
        if (r.status_code != 200):
            print("Some error occured while exchanging the authorization code, http code: " + str(r.status_code))
            print(r.text)
            sys.exit(1)
        return self.saveTokensAndGetAccessToken(r)


    #Attemps to get an access token, first from the datastore and if not present credentials will be asked 
    def getAccessToken(self):
        accessToken = self.getAccessTokenFromDatastoreOrRefresh()
        if (accessToken == None):
            return self.requestAccessTokenBasedOnUserCredentials()
        return accessToken


    #Utility method to save access and refresh token
    #Additionaly expiration_time is computed, based on the current time and the expires_in field
    def saveTokensAndGetAccessToken(self, response):
        print("Saving tokens information to datastore: " + self.datastore_filename)
        tokens = response.json()
        accessToken = tokens["access_token"]
        if(not hasattr(tokens, "expiration_time")):
            tokens["expiration_time"] = (int(time.time()) + int(tokens["expires_in"]))
        with open(self.datastore_filename, 'w') as outfile:
            json.dump(tokens, outfile)
        return accessToken


    #Fetches the realm's .well-known/openid-configuration once and caches it.
    #All endpoint lookups go through here, so the document is requested a single
    #time per KCAuth instance (and only when network access is actually needed).
    def getOpenidConfiguration(self):
        if(self.openid_configuration is None):
            wellKnownUrl = self.keycloak_realm_url + '.well-known/openid-configuration'
            print("Requesting .well-known openid-configuration: " + wellKnownUrl)
            self.openid_configuration = requests.get(wellKnownUrl).json()
        return self.openid_configuration


    #Builds (once) the full authorization endpoint URL including query params
    def getOrRequestAuthorizationEndPoint(self):
        #Assign it only once if needed
        if(len(self.authorization_endpoint) < 10):
            self.state = secrets.token_urlsafe(16)
            authorization_endpoint = self.getOpenidConfiguration()["authorization_endpoint"]+"?client_id="+urllib.parse.quote(self.client_id, safe='')+"&response_type=code&scope=openid&redirect_uri="+urllib.parse.quote(self.redirect_uri, safe='')+"&state="+self.state
            print("Authorization endpoint: " + authorization_endpoint)
            self.authorization_endpoint = authorization_endpoint
        
        return self.authorization_endpoint


    #Returns the 'token_endpoint' from the cached .well-known configuration
    def getOrRequestTokenEndPoint(self):
        return self.getOpenidConfiguration()["token_endpoint"]


    #Builds the kwargs for a token endpoint POST.
    #Instead of sending the raw client secret (e.g. via HTTP Basic auth), this
    #client authenticates with the "Signed JWT with Client Secret" method
    #(client_secret_jwt, RFC 7523 / OIDC Core). We build a short-lived JWT, sign
    #it with HMAC-SHA256 using the client secret as the key, and send it as a
    #client_assertion in the request body. The secret itself never travels over
    #the wire.
    def buildTokenRequestKwargs(self, payload):
        if(len(self.secret) > 0):
            payload = dict(payload)
            payload["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            payload["client_assertion"] = self.buildClientAssertion()
        return {"data": payload}


    #Base64url-encode without padding, as required by the JWS/JWT spec.
    def base64UrlEncode(self, raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


    #Builds and signs a client assertion JWT for the client_secret_jwt method.
    #The JWT is signed with HS256 using the client secret as the HMAC key, which
    #is what Keycloak expects when the client's "Client Authenticator" is set to
    #"Signed Jwt with Client Secret".
    def buildClientAssertion(self):
        now = int(time.time())
        # Keycloak's JWTClientSecretAuthenticator validates the assertion's
        # audience against the realm issuer URL (e.g.
        # http://localhost:8080/realms/test-realm), NOT the token endpoint.
        # Using the token endpoint here results in "unauthorized_client".
        issuer = self.getOpenidConfiguration()["issuer"]

        header = {
            "alg": "HS256",
            "typ": "JWT"
        }
        claims = {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": issuer,
            "jti": secrets.token_urlsafe(32),
            "iat": now,
            "exp": now + 60
        }

        signing_input = (
            self.base64UrlEncode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
            + "."
            + self.base64UrlEncode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        )
        signature = hmac.new(
            self.secret.encode("utf-8"),
            signing_input.encode("ascii"),
            hashlib.sha256
        ).digest()

        return signing_input + "." + self.base64UrlEncode(signature)


    def getUserInfo(self, token):
        userinfo_endpoint = self.getOpenidConfiguration()["userinfo_endpoint"]
        print("Requesting userinfo_endpoint: " + userinfo_endpoint)
        r = requests.get(userinfo_endpoint, headers={'Authorization': 'Bearer '+token})
        print (r)
        print(r.json())
        return r.json()["groups"]

    
    def __init__(self, configKcFile):
        with open(configKcFile) as f:
            data = json.load(f)

        self.datastore_filename = ".kc." + configKcFile.replace(".json", ".tokens")
        self.auth_server_url = data["auth-server-url"]
        if(self.auth_server_url.endswith("/")):
            print("!!!!!!!! auth-server-url should not end with '/', this script will likely fail !!!!!!!!!")
        self.realm = data["realm"]
        self.keycloak_realm_url = self.auth_server_url + "/realms/" + self.realm + "/"
        self.client_id = data["resource"]
        if("credentials" in data):
            self.secret = data["credentials"]["secret"]
        else:
            self.secret = ""
        self.openid_configuration = None
        self.authorization_endpoint = ""
        self.state = ""
        self.redirect_host = "127.0.0.1"
        self.redirect_port = 9000
        self.redirect_uri = "http://" + self.redirect_host + ":" + str(self.redirect_port) + "/callback"


if __name__ == '__main__':
    if(len(sys.argv) == 2):
        print("Using configuration file " + sys.argv[1])
        kcauth = KCAuth(sys.argv[1])
    else:
        defaultKeycloakFile = "keycloak.json"
        print("Keycloak configuration not passed as argument, taking default file name: " + defaultKeycloakFile)
        kcauth = KCAuth("keycloak.json")

    accessToken = kcauth.getAccessToken()
    print("\nYour access token:")
    print(accessToken)
    userInfo = kcauth.getUserInfo(accessToken)
    print("\nYour group info:")
    print(userInfo)
    