from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
import jinja2
import os

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)))

class RegisterMain(webapp.RequestHandler):
    def post(self):
        template = JINJA_ENVIRONMENT.get_template('index.html')
        templateValues = {}
        
        # Form response is the value that goes to the HTML page to send or view the public Key
        # TODO: Code to generate pub/prv key pair 
        templateValues = {'publicKey': 'Public Key'}
        
        self.response.headers['Content-Type'] = 'text/html'
        self.response.out.write(template.render(templateValues))
        
    def get(self):
        template = JINJA_ENVIRONMENT.get_template('index.html')
        templateValues = {}
        
        self.response.headers['Content-Type'] = 'text/html'
        self.response.out.write(template.render(templateValues))

class RegisterRedirect(webapp.RequestHandler):
    
    def post(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write('Register Completed!')



application = webapp.WSGIApplication([('/', RegisterMain),
                                      ('/registerRedirect', RegisterRedirect)], debug=True)


def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()
