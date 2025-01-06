from django.db import models
from django.contrib.auth.models import AbstractUser


class NoteSiteUser(AbstractUser):
    otp_secret = models.BinaryField()
    is_2fa_enabled = models.BooleanField(default=False)
    public_key = models.TextField(blank=True, null=True) 
    is_key_enabled = models.BooleanField(default=False)
    

    def __getitem__(self, key):
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"Key '{key}' does not exist in NoteSiteUser.")

class LoginIP(models.Model):
    user = models.ForeignKey(NoteSiteUser, on_delete=models.CASCADE, related_name='login_ips')
    ip_address = models.GenericIPAddressField()

class Follow(models.Model):
    follower = models.ForeignKey(NoteSiteUser, related_name='following', on_delete=models.CASCADE)
    following = models.ForeignKey(NoteSiteUser, related_name='followers', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

