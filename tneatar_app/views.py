from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render_to_response, redirect, render
from django.template import RequestContext
from django.contrib.auth.hashers import *
from tneatar_app.models import *
from django.db.models import Q
import random, rsa

# Create your views here.
def master(request):
    logged_user = logged_in_user(request)
    if isinstance(logged_user, User):
        tneatas = decrypt_followed_users_and_my_tneatas(logged_user)
        return render_to_response('master.html', {'tneatas':tneatas}, RequestContext(request))
    else:
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


def dashboard(request, username=None, dic=None):
    '''
        This function loads the logged in user and adds the content of the
        optionally passed dic to the dictionary that is sent to the template.

        if a username is passed, that would mean that a logged in user is trying
        to view the profile of another user whose username is the passed one.
    '''
    dic = dic or {}
    logged_user = logged_in_user(request)
    if logged_user:
        if username:
            try:
                user = User.objects.get(username=username)
                try:
                    Follow.objects.get(follower=logged_user, followed=user)
                    decrypt = True
                except Follow.DoesNotExist:
                    decrypt = False
            except User.DoesNotExist:
                return render_to_response('master.html', {'error': 'wrong username'}, RequestContext(request))
        else:
            user = logged_user
            decrypt = True
        tneats = decrypt_user_tneatas(user) if decrypt else []

        return render_to_response('dashboard.html', dict(dic, **{'user':user, 'tneats':tneats}), RequestContext(request))
    return render_to_response('master.html', {'error': 'please login'}, RequestContext(request))


def tneat(request):
    '''
        The Tneata is digitally signed using the owner's Private key,
        the followers can use the owner's Public key to verify
        the ownership of the tneata to the owner

        Tneatas are saved in DB in Base64,
        so it needs decoding before verification
    '''
    logged_user = logged_in_user(request)
    if isinstance(logged_user, User):
        if 'tneata' in request.POST:
            t = request.POST['tneata'].encode('utf-8')
            if len(t) > 0:
                signature = rsa.sign(t, logged_user.get_private_key(), 'SHA-1')
                signed_tneata = 'MMMMM'.join([t, signature])
                signed_tneata = signed_tneata.encode('Base64')
                tneat = Tneata.objects.create(user=logged_user, content=signed_tneata)
                return dashboard(request, dic={'success':'your tneata has just been published'})
            else:
                return dashboard(request, dic={'error':'you can not publish a blank tneata'})
        else:
            return dashboard(request, dic={'error':'error, try again later.'})
    else:
        return logged_user


def decrypt_followed_users_and_my_tneatas(user):
    '''
        Decrypts all tneatas by the user and the followed users

        Used in Home page
    '''
    r = []
    if user:
        tneatas = user.get_user_tneatas()
        if tneatas and user.get_followed_tneatas():
            tneatas = tneatas + user.get_followed_tneatas()
        for tneata in tneatas:
            t_content = tneata.content.decode('Base64')
            t, signature = t_content.split('MMMMM')
            if rsa.verify(t, signature, tneata.user.get_public_key()):
                r.append({'content':t, 'tneata':tneata})

    return r


def decrypt_user_tneatas(user):
    '''
        Decrypts all tneatas by the user

        Used in Dashboard and users' Profiles
    '''
    r = []
    tneatas = user.get_user_tneatas()
    print tneatas
    for tneata in tneatas:
        t_content = tneata.content.decode('Base64')
        t, signature = t_content.split('MMMMM')
        try:
            if rsa.verify(t, signature, tneata.user.get_public_key()):
                r.append({'content':t, 'tneata':tneata})
        except:
            pass
    return r


def send_message(request):
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
                recipient = User.objects.get(username=request.POST['recipient_username'])
                crypto = rsa.encrypt(request.POST['direct_message'].encode('utf-8'), recipient.get_public_key())
                signature = rsa.sign(crypto, user.get_private_key(), 'SHA-1')
                encryp_tneata = 'MMMMM'.join([crypto, signature])
                encryp_tneata = encryp_tneata.encode('Base64')
                print encryp_tneata
                dmsg = DirectMessage.objects.create(sender=user, recipient=recipient,  content=encryp_tneata)
            except User.DoesNotExist:
                return render_to_response('master.html', {'error': 'user not found'}, RequestContext(request))
        return render_to_response('master.html', {'error': 'error'}, RequestContext(request))
    return user


def index_messages(request):
    logged_user = logged_in_user(request)
    if isinstance(logged_user, User):
        users = logged_user.get_message_users()
        print users
        return render_to_response("messages.html", {'users':users}, RequestContext(request))
    else:
        return logged_user


def read_messages(request, username):
    r = []
    user = logged_in_user(request)
    if isinstance(user, User):
        try:
            user2 = User.objects.get(username=username)
            messages = DirectMessage.objects.filter(Q(sender=user, recipient=user2) | Q(sender=user2, recipient=user))
            pubkey2 = user2.get_public_key()
            privkey = user.get_private_key()

            for msg in messages:
                m_content = msg.content.decode('Base64')
                crypto, signature = m_content.split('MMMMM')
                if rsa.verify(crypto, signature, pubkey2):
                    m = rsa.decrypt(crypto, privkey)
                    r.append({'content':m, 'message':msg})
            return render_to_response('thread.html', {'msgs':r}, RequestContext(request))
        except User.DoesNotExist:
            return render_to_response('master.html', {'error': 'user not found'}, RequestContext(request))
    else:
        return user


def follow(request):
    user = logged_in_user(request)
    if user:
        if 'followed_username' in request.POST:
            try:
                followed = User.objects.get(username=request.POST['followed_username'])
                Follow.objects.create(follower=user, followed=followed)
            except User.DoesNotExist:
                return render_to_response('master.html', {'error': 'user not found'}, RequestContext(request))
    else:
        return user


def unfollow(request):
    user = logged_in_user(request)
    if user:
        if 'unfollowed_username' in request.POST:
            try:
                followed = User.objects.get(username=request.POST['unfollowed_username'])
                f = Follow.objects.get(follower=user, followed=followed)
                f.delete()
            except User.DoesNotExist:
                return render_to_response('master.html', {'error': 'user not found'}, RequestContext(request))
            except Follow.DoesNotExist:
                return render_to_response('master.html', {'error': 'The user needs to follow you first before you can unfollow request!'}, RequestContext(request))
    else:
        return user


def index_follow(request):
    user = logged_in_user(request)
    if user:
        followed =  user.get_followed()
        followers = user.get_followers()
        requests = user.get_follow_requests()
        return render_to_response("follow.html", {'followed':followed, 'followers':followers, 'requests':requests}, RequestContext(request))
    else:
        return user


def accept_follow(request):
    logged_user = logged_in_user(request)
    if logged_user:
        if 'follower_username' in request.POST:
            try:
                follower = User.objects.get(username=request.POST['followed_username'])
                f = Follow.objects.get(follower=follower, followed=logged_user)
                f.accepted = True
                f.save()
                return index_follow(request)
            except User.DoesNotExist:
                return render_to_response('master.html', {'error': 'user not found'}, RequestContext(request))
            except Follow.DoesNotExist:
                return render_to_response('master.html', {'error': 'The user needs to follow you first before you can accept the follow request!'}, RequestContext(request))
        else:
            return render_to_response('master.html', {'error': 'user not found'}, RequestContext(request))
    else:
        return logged_user


def tneatas_testing(request):
    return


def logged_in_user(request):
    if 'username' in request.session:
        try:
            return User.objects.get(username=request.session['username'])
        except User.DoesNotExist:
            return signin(request)
    return signin(request)


def extract_hashtags(tneata):
    matches = re.match(r".*?\s#(\w+)", tneata)
    hash_tags = []
    while matches:
        hash_tag = matches.group(1)
        hash_tags.append(hash_tag)
        beg = tneata.find("#%s" % hash_tag)
        tneata = tneata[(beg + 1 + len(hash_tag)) : ]
        matches = re.match(r".*?\s#(\w+)", tneata)

    return hash_tags


