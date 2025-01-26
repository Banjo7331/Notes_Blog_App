import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser


class NoteSiteUser(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(unique=True, max_length=15)
    email = models.EmailField(unique=True)
    otp_secret = models.BinaryField()
    is_2fa_enabled = models.BooleanField(default=False)
    is_key_enabled = models.BooleanField(default=False)
    

    def __getitem__(self, key):
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"Key '{key}' does not exist in NoteSiteUser.")

class Follow(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    follower = models.ForeignKey(NoteSiteUser, related_name='following', on_delete=models.CASCADE)
    following = models.ForeignKey(NoteSiteUser, related_name='followers', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

