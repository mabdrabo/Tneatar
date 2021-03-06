import random, re, rsa
from django.db import models

COLOR_CODE_CHOICES = ['A', 'B', 'C', 'D', 'E', 'F'] + range(0,10)
def random_color():
    return ''.join([str(n) for n in [random.choice(COLOR_CODE_CHOICES) for i in range(0,6)]])

# Create your models here.
class User(models.Model):
    username = models.CharField(unique=True,max_length=128)
    password = models.CharField(max_length=128)
    color = models.CharField(max_length=6, default=random_color)

    def get_keypair(self):
        keypair = Keypair.objects.get(user=self)
        return (rsa.PublicKey(2,3).load_pkcs1(keypair.public_key), rsa.PrivateKey(1, 2, 3, 4, 5, 6, 7, 8).load_pkcs1(keypair.private_key))

    def get_message_users(self):
        all_users = [m.sender for m in DirectMessage.objects.filter(recipient=self)]
        r = []
        r = [u for u in all_users if u not in r]
        return r

    def get_followed(self):
        return [f.followed for f in Follow.objects.filter(follower=self, accepted=True)]

    def get_followers(self):
        return [f.follower for f in Follow.objects.filter(followed=self, accepted=True)]

    def get_public_key(self):
        return self.get_keypair()[0]

    def get_private_key(self):
        return self.get_keypair()[1]

    def get_user_tneatas(self):
        return [t for t in Tneata.objects.filter(user=self)]

    def get_followed_tneatas(self):
        followed_tneatas = [f.get_user_tneatas() for f in self.get_followed()]
        return [t for sublist in followed_tneatas for t in sublist]

    def get_follow_requests(self):
        return Follow.objects.filter(followed=self, accepted=False)

    def set_keypair(self, pubkey, privkey):
        keypair, new_object = Keypair.objects.get_or_create(user=self)
        keypair.private_key = privkey.save_pkcs1()
        keypair.public_key = pubkey.save_pkcs1()
        keypair.save()
        return keypair

    def __unicode__(self):
        return self.username


class Keypair(models.Model):
    user = models.ForeignKey(User, related_name='keypair_owner')
    private_key = models.CharField(max_length=1024)
    public_key = models.CharField(max_length=1024)


class Tneata(models.Model):
    user = models.ForeignKey(User, related_name='tneata_owner')
    content = models.CharField(max_length=2048)
    retneat_from = models.ForeignKey(User, blank=True, null=True)

    def __unicode__(self):
        return "Tneata object " + str(self.pk)

class DirectMessage(models.Model):
    sender = models.ForeignKey(User, related_name='message_sender')
    recipient = models.ForeignKey(User, related_name='message_recipient')
    content = models.CharField(max_length=2048)

    def __unicode__(self):
        return "direct message object " + str(self.pk)


class Follow(models.Model):
    follower = models.ForeignKey(User, related_name='follower')
    followed = models.ForeignKey(User, related_name='followed')
    accepted = models.BooleanField(default=False)

    def set_accepted(self):
        self.accepted = True
        self.save()
        return self.accepted


class HashTag(models.Model):
    name = models.CharField(max_length=140)
    tneats = models.ManyToManyField(Tneata)
    weight = models.IntegerField(default=0)

    class Meta:
        ordering = ['-weight',]

    def __unicode__(self):
        return unicode(self.name)

    def add_tneata(self, tneata):
        self.tneats.add(tneata)
        self.weight = self.weight + 1
        self.save()

    def add_tneats(self, tneats):
        for tneata in tneats:
            self.add_tneata(tneata)
