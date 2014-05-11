from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render_to_response, redirect, render
from django.template import RequestContext
from django.utils import simplejson
from collections import OrderedDict
from tneatar_app.models import *

# Create your views here.
def master(request):
    return render_to_response('master.html', {}, RequestContext(request))


def signup(request):
    if request.POST:
        if 'username' in request.POST:
            user, new_object = User.objects.get_or_create(username=request.POST['username'])
            request.session['username'] = user.username
            return dashboard(request, dic={'success': "successfuly signed up and logged in as " + user.username})
    return render_to_response('master.html', {'error': 'enter your username'}, RequestContext(request))


def signin(request):
    if request.POST:
        if 'username' in request.POST:
            try:
                user = User.objects.get(username=request.POST['username'])
                request.session['username'] = user.username
                return dashboard(request, dic={'success': "you're logged in as " + user.username})
            except User.DoesNotExist:
                return render_to_response('master.html', {'error': 'user not found'}, RequestContext(request))
    return render_to_response('master.html', {'error': 'enter your username'}, RequestContext(request))


def signout(request):
    if 'username' in request.session:
        del request.session['username']
        return render_to_response('master.html', {'info': "You've Logged out"}, RequestContext(request))
    return render_to_response('master.html', {'info': "You've Logged out"}, RequestContext(request))


def dashboard(request, dic={}):
    if 'username' in request.session:
        try:
            user = User.objects.get(username=request.session['username'])
            objects, extras, locations = get_user_objects(user)
            return render_to_response('dashboard.html', dict(dic, **{'user': user, 'objects': objects, 'extras': extras}), RequestContext(request))
        except User.DoesNotExist:
            return render_to_response('dashboard.html', dict(dic, **{'error': 'user not found'}), RequestContext(request))
    return render_to_response('master.html', {'error': 'please login'}, RequestContext(request))

def email_send(request):
    if request.POST:
        if all(attr in request.POST for attr in ('email-from', 'email-subject', 'email-content')):
            from django.core.mail import send_mail
            send_mail(request.POST['email-subject'], request.POST['email-content'], request.POST['email-from'], ['abdrabo.mahmoud@gmail.com'], fail_silently=False)
            return render_to_response('contact.html', {'success': "email sent"}, RequestContext(request))
        else:
            return render_to_response('contact.html', {'error': "email Not sent, please try again later"}, RequestContext(request))
