from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render_to_response, redirect, render
from django.template import RequestContext
from django.contrib.auth.hashers import *
from tneatar_app.models import *
import random, rsa

# Create your views here.
def master(request):
    pubkey1, privkey1 = rsa.newkeys(1024, poolsize=8)
    pubkey2, privkey2 = rsa.newkeys(1024, poolsize=8)
    message = "Hello World!!"
    crypto = rsa.encrypt(message, pubkey1)
    print "crypto:", crypto
    signature = rsa.sign(crypto, privkey2, 'SHA-1')
    print "crypto:", crypto
    print "signature:", signature
    print rsa.verify(crypto, signature, pubkey2)
    message2 = rsa.decrypt(crypto, privkey1)
    print message2

    # fm = pubkey1.save_pkcs1(format='PEM')
    # print ">>>", fm
    # mf = rsa.PublicKey(2,3).load_pkcs1(fm, format='PEM')
    # print ">>>", mf
    # sg = privkey1.save_pkcs1(format='PEM')
    # print ">>>", sg
    # gs = rsa.PrivateKey(1, 2, 3, 4, 5, 6, 7, 8).load_pkcs1(sg, format='PEM')
    # print ">>>", gs

    return render_to_response('master.html', {}, RequestContext(request))


def signup(request):
    if request.POST:
        if 'username' in request.POST and 'password' in request.POST:
            user, new_object = User.objects.get_or_create(username=request.POST['username'])
            if not new_object:
                return render_to_response('master.html', {'info': 'account already exists, you can login'}, RequestContext(request))
            else:
                pubkey, privkey = rsa.newkeys(2048, poolsize=8)
                user.set_keypair(pubkey, privkey)
                user.password = make_password(password=request.POST['password'])
                user.save()
                request.session['username'] = user.username
                return dashboard(request, dic={'success': "successfuly signed up and logged in as " + user.username})
    return render_to_response('master.html', {'error': 'enter your username/password'}, RequestContext(request))


def signin(request):
    if request.POST:
        if 'username' in request.POST and 'password' in request.POST:
            try:
                user = User.objects.get(username=request.POST['username'])
                if check_password(request.POST['password'], user.password):
                    request.session['username'] = user.username
                    return dashboard(request, dic={'success': "you're logged in as " + user.username})
                else:
                    return render_to_response('master.html', {'error': 'wrong username/password'},RequestContext(request))
            except User.DoesNotExist:
                return render_to_response('master.html', {'error': 'user not found'}, RequestContext(request))
    return render_to_response('master.html', {'error': 'enter your username/password'}, RequestContext(request))


def signout(request):
    if 'username' in request.session:
        del request.session['username']
        return render_to_response('master.html', {'info': "You've Logged out"}, RequestContext(request))
    return render_to_response('master.html', {'info': "You've Logged out"}, RequestContext(request))


def dashboard(request, dic={}):
    if 'username' in request.session:
        try:
            user = User.objects.get(username=request.session['username'])
            return render_to_response('dashboard.html', dict(dic, **{'user': user, 'tneats': user.get_user_tneats()}), RequestContext(request))
        except User.DoesNotExist:
            return signout(request)
    return render_to_response('master.html', {'error': 'please login'}, RequestContext(request))


def tneat(request):
    '''
        The Tneata is encrypted and digitally signed using the owner's Private key,
        the followers can use the owner's Public key to decrypt and verify
        the ownership of the tneata to the owner

        Tneatas are saved in DB in Base64,
        so it needs decoding before decryption
    '''
    user = logged_in_user(request)
    if user:
        if 'tneata' in request.POST:
            crypto = rsa.encrypt(request.POST['tneata'].encode('utf-8'), user.get_private_key())
            signature = rsa.sign(crypto, user.get_private_key(), 'SHA-1')
            encryp_tneata = 'MMMMM'.join([crypto, signature])
            encryp_tneata = encryp_tneata.encode('Base64')
            tneat = Tneata.objects.create(user=user, content=encryp_tneata)


def decrypt_tneatas():
    '''
    '''
    user = logged_in_user(request)
    if user:
        tneatas = user.get


def send_direct_message(request):
    '''
        The message is encrypted using the recipient's Public key,
        the message is digitally signed using the sender's Private key,
        the recipient must use his own Private key to decrypt,
        and use the sender's Public key to verify ownership

        Messages are saved in DB in Base64,
        so it needs decoding before decryption
    '''
    user = logged_in_user(request)
    if user:
        if 'direct_message' in request.POST and 'recipient_username' in request.POST:
            try:
                recipient = User.objects.get(username=recipient_username)
                crypto = rsa.encrypt(request.POST['direct_message'].encode('utf-8'), recipient.get_public_key())
                signature = rsa.sign(crypto, user.get_private_key(), 'SHA-1')
                encryp_tneata = 'MMMMM'.join([crypto, signature])
                encryp_tneata = encryp_tneata.encode('Base64')
                tneat = Tneata.objects.create(user=user, content=encryp_tneata)

            except User.DoesNotExist:
                return


def follow(request):
    return


def unfollow(request):
    return


def email_send(request):
    if request.POST:
        if all(attr in request.POST for attr in ('email-from', 'email-subject', 'email-content')):
            from django.core.mail import send_mail
            send_mail(request.POST['email-subject'], request.POST['email-content'], request.POST['email-from'], ['abdrabo.mahmoud@gmail.com'], fail_silently=False)
            return render_to_response('contact.html', {'success': "email sent"}, RequestContext(request))
        else:
            return render_to_response('contact.html', {'error': "email Not sent, please try again later"}, RequestContext(request))


def logged_in_user(request):
    if 'username' in request.session:
        try:
            return User.objects.get(username=request.session['username'])
        except User.DoesNotExist:
            return None
    return None
