from django.db import models
from django.contrib.auth.models import AbstractUser
import pyotp


class NoteSiteUser(AbstractUser):
    otp_secret = models.CharField(max_length=32, default=pyotp.random_base32, blank=True, null=True)
    is_2fa_enabled = models.BooleanField(default=True) 
    follows = models.ManyToManyField(
        "self", related_name="followed_by", symmetrical=False, blank=True
    )

    def follow(self, user):
        if user != self:
            self.follows.add(user)

    def unfollow(self, user):
        if user != self:
            self.follows.remove(user)

    def is_following(self, user):
        return self.follows.filter(id=user.id).exists()

    def is_followed_by(self, user):
        return self.followed_by.filter(id=user.id).exists()

