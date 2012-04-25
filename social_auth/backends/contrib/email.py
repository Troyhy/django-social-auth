# coding=utf-8
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
from django.shortcuts import render, redirect

from social_auth.models import Nonce
from django.contrib.auth.models import User

from django.forms import EmailField, CharField,PasswordInput, Form

from django.template.loader import render_to_string
from social_auth.models import Nonce

from hashlib import md5
from time import time
from cmsplugin_plaintext.cms_plugins import CharFieldPlugin

from django.forms.util import ErrorList

from social_auth.signals import socialauth_registered
from social_auth.utils import settings

from django.contrib.sites.models import Site



EMAIL_TEMPLATE = setting('SOCIAL_AUTH_TOKEN_EMAIL_TEMPLATE','')
EMAIL_VIEW_TEMPLATE = setting('SOCIAL_AUTH_TOKEN_TEMPLATE','')



   

class EmailBackend(SocialAuthBackend):
    """Email authentication backend"""
    name = 'email'
    # Default extra data to store
    EXTRA_DATA = [
        ('id', 'id'),
        ('passwd', 'passwd'),
        ('expires', setting('SOCIAL_AUTH_EXPIRATION', 'expires'))
    ]
    
    def get_user_id(self, details, response):
        """Must return a unique ID from values returned on details"""
        print(response)
        try:
            return details['email']
        except KeyError:
            raise AuthFailed(self, 'Email not defined in auth process')
    
    def extra_data(self, user, uid, response, details):
        """Return default blank user extra data"""
        data={}
        if response.get('password'):
            data.update({'password':response['password']})
            
        return data
    
    def get_user_details(self, response):
        """Return user details from Github account"""
        return {USERNAME: response.get('login'),
                'email': response.get('email') or '',
                'first_name': response.get('name')}


# this stores user password to user object
def new_users_handler(sender, user, response, details, **kwargs):
    user.set_password(response['password'])
    user.save()
    try:
        Nonce.objects.get(server_url=user.email)
    except Nonce.DoesNotExist:
        pass
    return True

## register signal only if EmailBackend is activated
backends = setting('AUTHENTICATION_BACKENDS',{})
if 'social_auth.backends.contrib.email.EmailBackend' in backends:
    socialauth_registered.connect(new_users_handler, sender=EmailBackend)
    
class SocialAuthEmailForm(Form):
    social_auth_email = EmailField(max_length=50)
    social_auth_passwd = CharField(label=u'Salasana',widget=PasswordInput(render_value=False), required=False) 

class SocialAuthAskPasswordForm(Form):
    social_auth_passwd = CharField(label=u'Salasana',widget=PasswordInput(render_value=False), required=False) 
    
def EmailAuthPassword(req):
    form = SocialAuthAskPasswordForm(req.POST or None)
    context = {}
    if form.is_valid():
        req.session['social_auth_email_passwd'] = form.cleaned_data['social_auth_passwd']
        url = reverse('socialauth_complete',kwargs={'backend':'email'})+'?'+urlencode(req.GET)
        # continue with complete details
        # save aditional info for later use
        for field in req.POST:
            if field is not 'csrfmiddlewaretoken':
                req.session[field]= req.POST[field]
        
        return redirect(url)
    
    context.update({'form':form,
                    'ask_password':True})
    return render(req,EMAIL_VIEW_TEMPLATE,context)

def EmailAuthView(req):
    form = SocialAuthEmailForm(req.POST or None)
    context = {}
    if form.is_valid():
        email = form.cleaned_data['social_auth_email']
        passwd = form.cleaned_data['social_auth_passwd']
        
        ## password given, try to match against user password
        if len(passwd) != 0:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                errors = form._errors.setdefault("social_auth_email", ErrorList())
                errors.append(u"Sähköpostiosoitetta ei tunnistettu")
                context.update({'form':form})
                return render(req,EMAIL_VIEW_TEMPLATE,context)
            
            if not user.check_password(passwd):
                errors = form._errors.setdefault("social_auth_passwd", ErrorList())
                errors.append(u"Salasana on väärin, yritä uudestaan")
                context.update({'form':form})
                return render(req,EMAIL_VIEW_TEMPLATE,context)

            args ={'with_passwd':True}
            url = reverse('socialauth_complete',kwargs={'backend':'email'})+'?'+urlencode(args)  
            req.session['social_auth_email_passwd'] = passwd 
            req.session['social_auth_email_email'] = email
            return redirect(url)
      
        (item, created) = Nonce.objects.get_or_create(server_url=email,\
                                                      defaults={'timestamp': int(time())})
        if item.timestamp - int(time()) > (24 * 60 *60):
            created = True; # renew this token
        if created:
            real_salt=setting('SECRET_KEY','add more salt')
            item.salt = md5(real_salt + email +str(int(time()))).hexdigest()
            item.timestamp = int(time())
            item.save()
            
        args = {'token':item.salt}
        url = 'http://%s%s'%( Site.objects.get_current(),\
                              reverse('socialauth_complete',\
                                      kwargs={'backend':'email'})+'?'+urlencode(args))
        
        rendered = render_to_string(EMAIL_TEMPLATE, { 'auth_url': url })
        
        print('url:%s'%url)

        #send_email to form.cleaned_data['social_auth_email']
    else:
        context.update({'form':form})

    return render(req,EMAIL_VIEW_TEMPLATE,context)
    
class EmailAuth(BaseAuth):
    """E-mail Auth mechanism"""
    AUTH_BACKEND = EmailBackend
    
    

    def auth_url(self):
        """Returns redirect url"""
        return u'/email-auth/'

    def auth_complete(self, *args, **kwargs):
        """Returns user, might be logged in"""
        if 'token' not in self.data and 'with_passwd' not in self.data:
            error = self.data.get('error') or 'unknown error'
            raise AuthFailed(self, error)
        
        if not kwargs['request'].session.get('social_auth_email_passwd'):
            # password not in session, request new password
            kwargs['request'].session['social_auth_email_token'] = self.data['token']
            url = reverse('email-passwd')+'?'+urlencode({'token':self.data['token']})
            return redirect(url)
        
        if self.data.get('with_passwd'):
            self.data.get('with_passwd')
            data = {'email': kwargs['request'].session.get('social_auth_email_email'),
                    'passwd': kwargs['request'].session.get('social_auth_email_passwd')
                    }
        else:
            try:
                item = Nonce.objects.get(salt=self.data['token'])
            except Nonce.DoesNotExist as e:
                raise AuthFailed(self, e)
            
            
            data = {'email':item.server_url,
                    'password':kwargs['request'].session.get('social_auth_email_passwd'),}
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
