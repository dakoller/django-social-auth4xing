"""
XING OAuth support

No extra configurations are needed to make this work.
"""
from xml.etree import ElementTree
from xml.parsers.expat import ExpatError

from oauth2 import Token
import oauth2 as oauth

from social_auth.utils import setting
from social_auth.backends import ConsumerBasedOAuth, OAuthBackend, USERNAME
from social_auth.backends.exceptions import AuthCanceled, AuthUnknownError

from pprint import pprint

import settings
import simplejson as json

XING_SERVER = 'xing.com'
XING_REQUEST_TOKEN_URL = 'https://api.%s/v1/request_token' % \
                                    XING_SERVER
XING_ACCESS_TOKEN_URL = 'https://api.%s/v1/access_token' % \
                                    XING_SERVER
XING_AUTHORIZATION_URL = 'https://www.%s/v1/authorize' % \
                                    XING_SERVER
#XING_CHECK_AUTH = 'https://api.%s/v1/users/me.json' % XING_SERVER
XING_CHECK_AUTH = 'https://api.%s/v1/users/me.xml' % XING_SERVER

class XingBackend(OAuthBackend):
    """Xing OAuth authentication backend"""
    name = 'xing'
    EXTRA_DATA = [('id', 'id'),('user_id','user_id')]

    def get_user_details(self, response):
        """Return user details from Xing account"""
        pprint(response)
        first_name, last_name = response['first_name'], response['last_name']
        #first_name='Alfred E.'
        #last_name='Neumann'
        email = response.get('email', '')
        return {USERNAME: first_name + last_name,
                'fullname': first_name + ' ' + last_name,
                'first_name': first_name,
                'last_name': last_name,
                'email': email}


class XingAuth(ConsumerBasedOAuth):
    """Xing OAuth authentication mechanism"""
    AUTHORIZATION_URL = XING_AUTHORIZATION_URL
    REQUEST_TOKEN_URL = XING_REQUEST_TOKEN_URL
    ACCESS_TOKEN_URL = XING_ACCESS_TOKEN_URL
    SERVER_URL = 'api.%s' % XING_SERVER
    AUTH_BACKEND = XingBackend
    SETTINGS_KEY_NAME = 'XING_CONSUMER_KEY'
    SETTINGS_SECRET_NAME = 'XING_CONSUMER_SECRET'
    SCOPE_VAR_NAME=None
    SCOPE_SEPARATOR = '+'

    def user_data(self, access_token, *args, **kwargs):
        """Return user data provided"""
        url = XING_CHECK_AUTH
        
        consumer = oauth.Consumer(key=settings.XING_CONSUMER_KEY, secret=settings.XING_CONSUMER_SECRET)
        client= oauth.Client(consumer,access_token)
        
        resp, content = client.request('https://%s%s' % ('api.xing.com','/v1/users/me.json'), "GET")
        profile= json.loads(content)['users'][0]
        #pprint(profile)
        
        try:
            #return to_dict(ElementTree.fromstring(raw_xml))
            return {'user_id':profile['id'],'id':profile['id'],'first_name': profile['first_name'],'last_name': profile['last_name'],'email': profile['active_email']}
        except (ExpatError, KeyError, IndexError):
            return None

    def auth_complete(self, *args, **kwargs):
        """Complete auth process. Check Xing error response."""
        oauth_problem = self.request.GET.get('oauth_problem')
        if oauth_problem:
            if oauth_problem == 'user_refused':
                raise AuthCanceled(self, '')
            else:
                raise AuthUnknownError(self, 'Xing error was %s' %
                                                    oauth_problem)
        return super(XingAuth, self).auth_complete(*args, **kwargs)

    def get_scope(self):
        """Return list with needed access scope"""
        scope = []
        if self.SCOPE_VAR_NAME:
            scope = setting(self.SCOPE_VAR_NAME, [])
        else:
            scope = []
        return scope

    def unauthorized_token(self):
        """Makes first request to oauth. Returns an unauthorized Token."""
        request_token_url = self.REQUEST_TOKEN_URL
        scope = self.get_scope()
        if scope:
            qs = 'scope=' + self.SCOPE_SEPARATOR.join(scope)
            request_token_url = request_token_url + '?' + qs

        request = self.oauth_request(
            token=None,
            url=request_token_url,
            extra_params=self.request_token_extra_arguments()
        )
        response = self.fetch_response(request)
        return Token.from_string(response)


def to_dict(xml):
    """Convert XML structure to dict recursively, repeated keys entries
    are returned as in list containers."""
    children = xml.getchildren()
    if not children:
        return xml.text
    else:
        out = {}
        for node in xml.getchildren():
            if node.tag in out:
                if not isinstance(out[node.tag], list):
                    out[node.tag] = [out[node.tag]]
                out[node.tag].append(to_dict(node))
            else:
                out[node.tag] = to_dict(node)
        return out


# Backend definition
BACKENDS = {
    'xing': XingAuth,
}
