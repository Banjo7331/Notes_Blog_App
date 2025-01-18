import uuid
from django.db import models
from .utils import sanitize_markdown
from notes_keeping_site import settings
# Create your models here.

class Note(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notes")
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE,related_name="received_notes",null=True,blank=True) 
    is_private = models.BooleanField(default=False)
    title = models.CharField(max_length=255)
    serialized_content = models.TextField()
    signature = models.TextField(null=True, blank=True)
    likes = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='note_like')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def number_of_likes(self):
        return self.likes.count()

    def __str__(self):
        return self.title
