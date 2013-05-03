from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
import jinja2
import os

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)))

class RegisterMain(webapp.RequestHandler):

    def get(self):
        self.response.headers['Content-Type'] = 'text/html'
        self.response.out.write('<form method="POST" action="registerComplete" > <input type="submit" /> </form>')

class RegisterComplete(webapp.RequestHandler):
    
    def post(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write('Register Completed!')

application = webapp.WSGIApplication([('/', RegisterMain),
                                      ('/registerComplete', RegisterComplete)], debug=True)


def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()
