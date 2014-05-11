from django.db import models

# Create your models here.
class User(models.Model):
    username = models.CharField(unique=True,max_length=128)
    password = models.CharField(max_length=128)

    def get_keypair(self):
        return Keypair.objects.get(user=self)

    def get_public_key(self):
        return get_keypair()[0]

    def get_public_key(self):
        return get_keypair()[1]

    def get_tneats(self):
        return Tneata.objects.filter(user=self)

    def get_follow_requests(self):
        return Follow.objects.filter(followed=self, accepted=False)


class Keypair(models.Model):
    user = models.ForeignKey(User, related_name='owner')
    private_key = models.CharField(max_length=1024)

    def get_public_key(self):
        return


class Tneata(models.Model):
    user = models.ForeignKey(User, related_name='tneata_owner')
    content = models.CharField(max_length=128)
    retweet_count = models.IntegerField()


class Follow(models.Model):
    follower = models.ForeignKey(User, related_name='follower')
    followed = models.ForeignKey(User, related_name='followed')
    accepted = models.BooleanField(default=False)

    def set_accepted(self):
        self.accepted = True
        self.save()
        return self.accepted
