from django.contrib import admin
from .models import Follow, NoteSiteUser

# Register your models here.

admin.site.register(NoteSiteUser)
admin.site.register(Follow)

