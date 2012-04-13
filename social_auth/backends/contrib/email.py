"""
Social E-mail auth.

This contribution adds support for authentication via email"""
import cgi
from urllib import urlencode, urlopen

from django.utils import simplejson
from django.contrib.auth import authenticate

from social_auth.utils import setting
from social_auth.backends import BaseAuth, SocialAuthBackend, USERNAME
from social_auth.backends.exceptions import AuthFailed

from django.http import HttpResponseRedirect, HttpResponse, \
                        HttpResponseServerError
from django.core.urlresolvers import reverse
from django.shortcuts import render

from social_auth.models import Nonce

from django.forms import EmailField, Form

from django.template.loader import render_to_string
from social_auth.models import Nonce

from hashlib import md5
from time import time

class EmailBackend(SocialAuthBackend):
    """Github OAuth authentication backend"""
    name = 'email'
    # Default extra data to store
    EXTRA_DATA = [
        ('id', 'id'),
        ('email', 'email'),
        ('expires', setting('SOCIAL_AUTH_EXPIRATION', 'expires'))
    ]
    
    def get_user_id(self, details, response):
        """Must return a unique ID from values returned on details"""
        print(response)
        try:
            return details['email']
        except KeyError:
            raise AuthFailed(self, 'Email not defined in auth process')
    

    def get_user_details(self, response):
        """Return user details from Github account"""
        return {USERNAME: response.get('login'),
                'email': response.get('email') or '',
                'first_name': response.get('name')}


class SocialAuthEmailForm(Form):
    social_auth_email = EmailField(max_length=50)


def EmailAuthView(req):
    form = SocialAuthEmailForm(req.POST or None)
    context = {}
    if form.is_valid():
        email = form.cleaned_data['social_auth_email']
        (item, created) = Nonce.objects.get_or_create(server_url=email,defaults={'timestamp': int(time())})
        if item.timestamp - int(time()) > (24 * 60 *60):
            created = True; # renew this token
        if created:
            item.salt = md5('suolattu juttu' + email).hexdigest()
            item.timestamp = int(time())
            item.save()
            
        args = {'token':item.salt}
        url = reverse('socialauth_complete',kwargs={'backend':'email'})+urlencode(args)
        rendered = render_to_string('promo2/auth/email.txt', { 'auth_url': url })
        print('url:%s'%url)
        #send_email to form.cleaned_data['social_auth_email']
    else:
        context.update({'form':form})

    return render(req,"promo2/email_view.html",context)
    
class EmailAuth(BaseAuth):
    """E-mail Auth mechanism"""
    AUTH_BACKEND = EmailBackend
    
    

    def auth_url(self):
        """Returns redirect url"""
        return u'/email-auth/'

    def auth_complete(self, *args, **kwargs):
        """Returns user, might be logged in"""
        if 'token' not in self.data:
            error = self.data.get('error') or 'unknown error'
            raise AuthFailed(self, error)
        
        try:
            item = Nonce.objects.get(salt=self.data['token'])
        except Nonce.DoesNotExist as e:
            raise AuthFailed(self, e)
        
        
        data = self.user_data(item)
        if data is not None:
            if 'error' in data:
                error = self.data.get('error') or 'unknown error'
                raise AuthFailed(self, error)

        kwargs.update({
            'auth': self,
            'response': data,
            self.AUTH_BACKEND.name: True
        })
        return authenticate(*args, **kwargs)

    def user_data(self, item):
        """Loads user data from service"""
        data = {'email': item.server_url,
                }
        try:
            return data
        except ValueError:
            return None

    @classmethod
    def enabled(cls):
        """Return backend enabled status by checking basic settings"""
        return True


# Backend definition
BACKENDS = {
    'email': EmailAuth,
}
