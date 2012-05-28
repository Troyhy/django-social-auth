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

from social_auth.models import UserSocialAuth
 
from django.http import HttpResponseRedirect, HttpResponse, \
                        HttpResponseServerError
from django.core.urlresolvers import reverse
from django.shortcuts import render, redirect


from django.contrib.auth.models import User

from django.forms import EmailField, CharField,PasswordInput, Form, ValidationError

from django.template.loader import render_to_string
from social_auth.models import Nonce

from hashlib import md5
from time import time
from cmsplugin_plaintext.cms_plugins import CharFieldPlugin

from django.forms.util import ErrorList

from social_auth.signals import socialauth_registered
from social_auth.utils import settings

from django.contrib.sites.models import Site

from django.core.mail import send_mail
from django.forms.fields import BooleanField, ChoiceField

## spagetti!!!
from promo2.utils import random_face_url


EMAIL_TEMPLATE = setting('SOCIAL_AUTH_TOKEN_EMAIL_TEMPLATE','')
EMAIL_SUBJECT_TEMPLATE = setting('SOCIAL_AUTH_TOKEN_EMAIL_SUBJECT_TEMPLATE','')
EMAIL_FROM = setting('SOCIAL_AUTH_TOKEN_EMAIL_FROM','noreply@example.com') 
EMAIL_VIEW_TEMPLATE = setting('SOCIAL_AUTH_TOKEN_TEMPLATE','')

EMAIL_AUTH_FIELDS =['passwd', 'email' ,'first_name','last_name','gender','hometown']


DEBUG = setting('DEBUG','False')

 # generate password
def create_password(raw_password):
    from django.contrib.auth.models import get_hexdigest
    import random
    algo = 'sha1'
    salt = get_hexdigest(algo, str(random.random()), str(random.random()))[:5]
    hsh = get_hexdigest(algo, salt, raw_password)
    return '%s$%s$%s' % (algo, salt, hsh)

   

class EmailBackend(SocialAuthBackend):
    """Email authentication backend"""
    name = 'email'
    # Default extra data to store
    EXTRA_DATA = [
        ('password', 'password'),
    ]
    
    def get_user_id(self, details, response):
        """Must return a unique ID from values returned on details"""
        print(response)
        try:
            return details['email']
        except KeyError:
            raise AuthFailed(self, 'Email not defined in auth process')
    
        
    def extra_data(self, user, uid, response, details):
        """Return access_token and extra defined names to store in
        extra_data field"""
        data = {}
        name = self.name.replace('-', '_').upper()
        names = (self.EXTRA_DATA or []) + setting(name + '_EXTRA_DATA', [])
        
            
        for entry in names:
            if len(entry) == 2:
                (name, alias), discard = entry, False
            elif len(entry) == 3:
                name, alias, discard = entry
            elif len(entry) == 1:
                name = alias = entry
            else:  # ???
                continue

            value = response.get(name)
            if discard and not value:
                continue
            data[alias] = value
        return data
    
    
    def get_user_details(self, response):
        """Return details from responce"""
        
        data = {USERNAME: response.get('login'),
                'email': response.get('email','') ,
                'first_name': response.get('first_name',''),
                'last_name': response.get('last_name',''),
                'password': response.get('password',''),
                
                }
        return data

    
class SocialAuthEmailForm(Form):
    social_auth_email = EmailField(max_length=50)
    social_auth_passwd = CharField(label=u'Salasana',widget=PasswordInput(render_value=False), required=False) 

class SocialAuthNewEmailForm(Form):
    social_auth_email = EmailField(label=u'Sähköpostiosoite', max_length=50)
    
     # possible other intresting parts here

    def clean_social_auth_email(self):
        try:
            User.objects.get(email=self.cleaned_data['social_auth_email'])
        except User.DoesNotExist:
            return self.cleaned_data['social_auth_email']
        else:
            raise ValidationError(u'Sähköpostiosoite on jo käytössä, '
                                  u'Kirjaudu sisään käyttämällä salasanaa')
GENDER = (
    ('m', 'Mies'),
    ('f', 'Nainen'),
)  



from django.contrib.localflavor.fi.forms import FIMunicipalitySelect
from django.contrib.localflavor.fi.fi_municipalities import MUNICIPALITY_CHOICES
MUNICIPALITY_EMPTY = [('','Valitse Paikkakunta')] +list( MUNICIPALITY_CHOICES)
class SocialAuthAskPasswordForm(Form):
    first_name = CharField(label=u'Etunimi', max_length=20)
    last_name = CharField(label=u'Sukunimi', max_length=30)
    gender = ChoiceField(label=u'Sukupuoli', choices=GENDER)
    hometown = ChoiceField(label=u'Paikkakunta', choices=MUNICIPALITY_EMPTY, required=False )
   
    
    social_auth_passwd = CharField(label=u'Salasana',widget=PasswordInput(render_value=False)) 
    social_auth_passwd2 = CharField(label=u'Salasana2',widget=PasswordInput(render_value=False)) 
    
    def clean(self):
        cleaned_data = super(SocialAuthAskPasswordForm, self).clean()
        passwd1 = cleaned_data.get('social_auth_passwd')
        passwd2 = cleaned_data.get('social_auth_passwd2' )
        
        if passwd1 != passwd2:
            msg = u"Salasanakentät eivät täsmää!"
            self._errors["social_auth_passwd2"] = self.error_class([msg])
            try:
                del cleaned_data['social_auth_passwd2']
            except:
                pass
        return cleaned_data  
    
def EmailAuthPassword(req):
    form = SocialAuthAskPasswordForm(req.POST or None)
    context = {}
    if form.is_valid():
        req.session['social_auth_email_passwd'] = form.cleaned_data['social_auth_passwd']
        url = reverse('socialauth_complete',kwargs={'backend':'email'})+'?'+urlencode(req.GET)
        # continue with complete details
        # save aditional info for later use
        for field in req.POST:
            if field in EMAIL_AUTH_FIELDS:
                req.session['social_auth_email_'+str(field)]= req.POST[field]
        
        return redirect(url)
    
    context.update({'form':form,
                    'ask_password':True})
    return render(req,EMAIL_VIEW_TEMPLATE,context)

def EmailAuthView(req):    
    context = {}
    create_new_account = 'create_new_account' in req.GET 
    context.update({'create_new_account':create_new_account})
    
    if create_new_account:
        form = SocialAuthNewEmailForm(req.POST or None)
    else:
        form = SocialAuthEmailForm(req.POST or None)
        
    if form.is_valid():
        email = form.cleaned_data['social_auth_email']
        passwd = ''
        if 'social_auth_passwd' in form.cleaned_data:
            passwd = form.cleaned_data['social_auth_passwd']
       
        ## password given, try to match against user password
        if not create_new_account:
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
        
        else:     
            (item, created) = Nonce.objects.get_or_create(server_url=email,\
                                                          defaults={'timestamp': int(time())})
            if item.timestamp - int(time()) > (24 * 60 *60):
                created = True; # renew this token
            if created:
                real_salt=setting('SECRET_KEY','add more salt')
                item.salt = md5(real_salt + email +str(int(time()))).hexdigest()
                item.timestamp = int(time())
                item.save()
                
            context.update({'email':email})   
            args = {'token':item.salt}
            url = 'http://%s%s'%( Site.objects.get_current(),\
                                  reverse('socialauth_complete',\
                                          kwargs={'backend':'email'})+'?'+urlencode(args))
            
            rendered = render_to_string(EMAIL_TEMPLATE, { 'auth_url': url })
            subject =  render_to_string(EMAIL_SUBJECT_TEMPLATE, { 'auth_url': url })
            send_mail(subject, rendered , EMAIL_FROM,[email], fail_silently=False)
            if DEBUG:
                print('url:%s'%url)

    else:
        context.update({'form':form})

    return render(req,EMAIL_VIEW_TEMPLATE,context)


class EmailAuth(BaseAuth):
    """E-mail Auth mechanism"""
    AUTH_BACKEND = EmailBackend
    
    def auth_html(self,req, *args, **kwargs):
        for field in EMAIL_AUTH_FIELDS:
            try: # clear previous try
                del req.session['social_auth_email_'+field]
            except:
                pass  
        return EmailAuthView(req, *args, **kwargs)

    def auth_complete(self, *args, **kwargs):
        """Returns user, might be logged in"""
        req = kwargs['request']
        item = None
        
        if 'token' not in self.data and 'with_passwd' not in self.data:
            error = self.data.get('error') or 'unknown error'
            raise AuthFailed(self, error)
        
        if 'token' in self.data:
            try:
                item = Nonce.objects.get(salt=self.data['token'])
            except Nonce.DoesNotExist as e:
                raise AuthFailed(self, e)
            
        if not req.session.get('social_auth_email_passwd'):
            # password not in session, request new password
            kwargs['request'].session['social_auth_email_token'] = self.data['token']
            req=kwargs['request']
            return EmailAuthPassword(req)
              
        if self.data.get('with_passwd'):
            social_data = UserSocialAuth.objects.filter(uid=req.session.get('social_auth_email_email'))[0]
            
            data = {'email': social_data.user.email,
                    }
            ## append other data 
            data.update(social_data.extra_data)
            
        else:
            data = {'email': item.server_url,
                    'password': create_password(req.session.get('social_auth_email_passwd')),
                    }
            # copy all gathered data from session to responce 
            for (name, value) in req.session.iteritems():
                if name.startswith('social_auth_email_'):
                    data.update({name[18:]:value})
                   
            if data is not None: #there cannot be error, left here for reference
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
    
    @property
    def uses_redirect(self):
        """Return True if this provider uses redirect url method,
        otherwise return false."""
        return False
    
    @classmethod
    def enabled(cls):
        """Return backend enabled status by checking basic settings"""
        return True


# Backend definition
BACKENDS = {
    'email': EmailAuth,
}
