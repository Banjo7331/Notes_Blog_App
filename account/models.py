from django.db import models
from django.contrib.auth.models import AbstractUser
import pyotp

# Create your models here.

class NoteSiteUser(AbstractUser):
    otp_secret = models.CharField(max_length=32, default=pyotp.random_base32, blank=True, null=True)
    is_2fa_enabled = models.BooleanField(default=True) 