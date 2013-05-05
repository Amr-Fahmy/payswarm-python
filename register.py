import datetime
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
import jinja2
import os
from Crypto.PublicKey import RSA

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)))

class WebKeyIdentity(db.Model):
    public_key = db.TextProperty(required=True)
    private_key = db.TextProperty(required=True)
    creation_date = db.DateTimeProperty(required=True, auto_now_add=True)
    payswarm_identity = db.StringProperty()
    payswarm_key = db.StringProperty(indexed=False)
    payswarm_financial_account = db.StringProperty(indexed=False)
    is_registered = db.BooleanProperty(required=True,default=False,indexed=False)
    registration_date = db.DateTimeProperty()
    
class RegisterMain(webapp.RequestHandler):
    def renderTemplate(self, webkey):
        template = JINJA_ENVIRONMENT.get_template('index.html')
        templateValues ={}
        
        if webkey:
            templateValues = {'publicKey': webkey.public_key, 'privateKey': webkey.private_key} 

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
        publicKey = rsakey.publickey().exportKey('PEM')
        privateKey = rsakey.exportKey('PEM', 'P@y5w@rm2013')        
        # TODO: Store the generated key pair in DB 
        webkey = WebKeyIdentity(public_key=publicKey,
                                private_key=privateKey)
        webkey.put()
        self.renderTemplate(webkey) 
        # Display results
        
    def get(self):
        webkeys = db.GqlQuery("SELECT * FROM WebKeyIdentity LIMIT 1")
        webkey = None
        
        if webkeys.count(1)>0:
            [webkey] = webkeys

        self.renderTemplate(webkey)

class RegisterRedirect(webapp.RequestHandler):
    
    def post(self):
        configServiceIRI = self.request.get['auth_url']
        if configServiceIRI:
            configServiceIRI += '/.well-known/web-keys'
            publicKey = ''
            
            #Send HTTPS to configServiceIRI
            #Accept: application/ld+json; form=compacted
            #
            #Expected example response:
            """
            {
              "@context": "https://w3id.org/payswarm/v1",
              "publicKeyService": "https://dev.payswarm.com/i?form=register"
            }
            """
            configResp = {} #parse the JSON response
            
            # Validate that @context == https://w3id.org/payswarm/v1, e.g.:
            #if configResp['@context'] != 'https://w3id.org/payswarm/v1'

            # Get the value of publicKeyService from response
            regURL = configResp['publicKeyService']
            
            #randomNonce = Random Hex String of length 16
            #regURL.addQueryParameter('public-key', publicKey)
            #regURL.addQueryParameter('registration-callback', 'http://localhost:8080/registerCallback')
            #regURL.addQueryParameter('response-nonce', randomNonce)
            
            #Redirect to regURL
            self.redirect(regURL, True)


class RegisterCallback(webapp.RequestHandler):
    def post(self):
        # Just print the publicKey URL
        self.response.out.write("")      

application = webapp.WSGIApplication([('/', RegisterMain),
                                      ('/registerRedirect', RegisterRedirect),
                                      ('/registerCallback', RegisterCallback )], debug=True)


def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()
