from django.db import models
import rsa

# Create your models here.
class User(models.Model):
    username = models.CharField(unique=True,max_length=128)
    password = models.CharField(max_length=128)

    def get_keypair(self):
        keypair = Keypair.objects.get(user=self)
        return (rsa.PublicKey(2,3).load_pkcs1(keypair.public_key), rsa.PrivateKey(1, 2, 3, 4, 5, 6, 7, 8).load_pkcs1(keypair.private_key))

    def get_public_key(self):
        return self.get_keypair()[0]

    def get_private_key(self):
        return self.get_keypair()[1]

    def get_user_tneats(self):
        return Tneata.objects.filter(user=self)

    def get_followed_tneats(self):    # TODO
        return Tneata.objects.filter(user=self)

    def get_follow_requests(self):
        return Follow.objects.filter(followed=self, accepted=False)

    def set_keypair(self, pubkey, privkey):
        keypair, new_object = Keypair.objects.get_or_create(user=self)
        keypair.private_key = privkey.save_pkcs1()
        keypair.public_key = pubkey.save_pkcs1()
        keypair.save()
        return keypair


class Keypair(models.Model):
    user = models.ForeignKey(User, related_name='keypair_owner')
    private_key = models.CharField(max_length=1024)
    public_key = models.CharField(max_length=1024)


class Tneata(models.Model):
    user = models.ForeignKey(User, related_name='tneata_owner')
    content = models.CharField(max_length=2048)
    retneat_count = models.IntegerField(default=0)

    def __unicode__(self):
        return "Tneata object"


class DirectMessage(models.Model):
    sender = models.ForeignKey(User, related_name='message_sender')
    recipient = models.ForeignKey(User, related_name='message_recipient')
    content = models.CharField(max_length=2048)

    def __unicode__(self):
        return "direct message object"


class Follow(models.Model):
    follower = models.ForeignKey(User, related_name='follower')
    followed = models.ForeignKey(User, related_name='followed')
    accepted = models.BooleanField(default=False)

    def set_accepted(self):
        self.accepted = True
        self.save()
        return self.accepted
