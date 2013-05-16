import datetime
import webapp2
from webapp2_extras import sessions
from google.appengine.ext import db
from google.appengine.ext.webapp.util import run_wsgi_app
import jinja2
import os
import socket
from urllib2 import Request
import textwrap
from datetime import datetime, timedelta
#from test.test_zipfile import DecryptionTests
os.name = 'posix'
from google.appengine.api import mail
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import httplib
import urllib
import urllib2
import json
from Crypto.Cipher import PKCS1_OAEP
import datetime
import binascii

class WebKeyIdentity(db.Model):
    public_key = db.TextProperty(required=True)
    private_key = db.TextProperty(required=True)
    creation_date = db.DateTimeProperty(required=True, auto_now_add=True)
    payswarm_identity = db.StringProperty()
    payswarm_key = db.StringProperty(indexed=False)
    payswarm_financial_account = db.StringProperty(indexed=False)
    is_registered = db.BooleanProperty(required=True,default=False,indexed=False)
    registration_date = db.DateTimeProperty()
    
class BaseHandler(webapp2.RequestHandler):
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()
    
JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)))  

class RegisterMainHandler(BaseHandler):
    def renderTemplate(self, webkey):
        template = JINJA_ENVIRONMENT.get_template('index.html')
        templateValues ={}
        if webkey:
            templateValues = {'publicKey': webkey.public_key}    
        # Display results
        self.response.headers['Content-Type'] = 'text/html'
        self.response.out.write(template.render(templateValues))
         
    
    def post(self):
        # TODO: Get old key
        webkeys = db.GqlQuery("SELECT * FROM WebKeyIdentity LIMIT 1")
        if webkeys.count(1)>0:
            [webkey] = webkeys
            webkey.delete()
        
        # TODO: Code to generate pub/prv key pair 
        rsakey = RSA.generate(2048)
        publicKey = rsakey.publickey().exportKey("PEM")
        privateKey = rsakey.exportKey()        
        # TODO: Store the generated key pair in DB 
        webkey = WebKeyIdentity(public_key=publicKey,
                                private_key=privateKey)
        webkey.put()    
        self.session['publicKey'] = publicKey

        self.renderTemplate(webkey) 
        # Display results
        
    def get(self):
        webkeys = db.GqlQuery("SELECT * FROM WebKeyIdentity LIMIT 1")
        webkey = None
        
        if webkeys.count(1)>0:
            [webkey] = webkeys
            self.session['publicKey'] = webkey.public_key
            
        self.renderTemplate(webkey)


class RegisterRedirectHandler(BaseHandler):
    
    def post(self):
            publicKey = self.session.get('publicKey')
                  
            configServiceIRI = self.request.get('auth_url')
            if configServiceIRI:
                #configServiceIRI += '/.well-known/web-keys'
                
                #Send HTTPS to configServiceIRI
                #Accept: application/ld+json; form=compacted
                # conn = httplib.HTTPSConnection(configServiceIRI)
                #conn.request(method, url, body, headers)
                jsonLdResponse = '{'\
                        '"@context": "https://w3id.org/payswarm/v1",'\
                        '"publicKeyService": "https://dev.payswarm.com/i?form=register"}'
                
                if False:
                    headers = {"Accept": "application/ld+json; form=compacted"}
                    conn = httplib.HTTPSConnection(configServiceIRI)
                    conn.request("GET", "/.well-known/web-keys",None, headers)
                    httpResponse = conn.getresponse()
                    jsonLdResponse = httpResponse.read()
                
                #Expected example response:
                """
                    {
                        "@context": "https://w3id.org/payswarm/v1",
                        "publicKeyService": "https://dev.payswarm.com/i?form=register"
                    }
                """
                
                jsonLdObject = json.loads(jsonLdResponse)

                # Validate that @context == https://w3id.org/payswarm/v1, e.g.:
                #if configResp['@context'] != 'https://w3id.org/payswarm/v1'
                if jsonLdObject['@context'] != 'https://w3id.org/payswarm/v1':
                    raise Exception('Invalid JSON LD @context')

    
                # Get the value of publicKeyService from response
                regURL = jsonLdObject['publicKeyService']
                
                randomData = os.urandom(128)
                randomNonce = hashlib.md5(randomData).hexdigest()[:16]
                
                #randomNonce = Random Hex String of length 16
                
                regParams = {'public-key': publicKey,
                             'registration-callback': "http://"+socket.gethostname()+"/registerCallback",
                             'response-nonce': randomNonce }
                self.session['nonce']= randomNonce

                #regURL.addQueryParameter('public-key', publicKey)
                #regURL.addQueryParameter('registration-callback', 'http://localhost:8080/registerCallback')
                #regURL.addQueryParameter('response-nonce', randomNonce)
                
                regURL += "&" + urllib.urlencode(regParams)
                #Redirect to regURL
                self.redirect(regURL, True)
               
            #templateValues={'value': hashlib.md5(random_data).hexdigest()[:16]}
            #self.response.out.write(template.render(templateValues))

class RegisterCallbackHandler(BaseHandler):
    def post(self):
        # Just print the publicKey URL
        dataJson = self.request.get("encrypted-message")
        dataObject = json.loads(dataJson,encoding="UTF-8")
        #self.response.write(dataObject)
        if True:
            webkeys = db.GqlQuery("SELECT * FROM WebKeyIdentity LIMIT 1")
            [webkey]= webkeys
            key=RSA.importKey(webkey.private_key)
            PKCSCipher = PKCS1_OAEP.new(key)
            #self.response.write(webkey.private_key)

            iv_enc = dataObject['initializationVector']
            ivec_enc = binascii.a2b_base64(iv_enc)
            ivec = PKCSCipher.decrypt(ivec_enc)

            encKeyec_enc = dataObject['cipherKey']
            encKey_enc = binascii.a2b_base64(encKeyec_enc)
            encKey = PKCSCipher.decrypt(encKey_enc)    

            dataec_enc = dataObject['cipherData']
            data_enc = binascii.a2b_base64(dataec_enc)
            AESCipher = AES.new(key=encKey, mode=AES.MODE_CBC, IV=ivec )
            data = AESCipher.decrypt(data_enc)
            #self.response.write(data)    
            #data after dyc. it
            DecdataObject = json.loads(data,encoding="UTF-8")
            decType = DecdataObject["type"]     
            decOwner = DecdataObject["owner"]  
            decDestination = DecdataObject["destination"] 
            decPublicKey = DecdataObject["publicKey"]
            decContext =  DecdataObject["@context"]
            decSigType = DecdataObject["signature"]["type"]
            decSigCreator = DecdataObject["signature"]["creator"]
            decSigCreated = DecdataObject["signature"]["created"]
            decSigSignatureValue = DecdataObject["signature"]["signatureValue"]
            decSigNonce = DecdataObject["signature"]["nonce"]
            registerationDate = datetime.datetime.now()
            decSigCreated = datetime.datetime.strptime(decSigCreated , '%Y-%m-%dT%H:%M:%SZ')

            if (self.session['nonce']==decSigNonce):    
                webkey = WebKeyIdentity(public_key=webkey.public_key,
                                        private_key=webkey.private_key,
                                        creation_date = decSigCreated ,
                                        payswarm_identity = decOwner , 
                                        payswarm_key = decPublicKey , 
                                        payswarm_financial_account = decDestination, 
                                        is_registered = True, 
                                        registration_date = registerationDate)
                webkey.put()    
                #registered = "True"
                #self.session['registered']=registered
               

                self.redirect("/",True)
            
            #st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            
            #self.response.write(self.session['nonce'])

config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': 'aBc123DeF'
}
application = webapp2.WSGIApplication([('/', RegisterMainHandler),
                                      ('/registerRedirect', RegisterRedirectHandler),
                                      ('/registerCallback', RegisterCallbackHandler )], 
                                      debug=True,
                                      config=config)


def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()
