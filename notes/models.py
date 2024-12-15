from django.db import models
from .utils import sanitize_markdown
from notes_keeping_site import settings

# Create your models here.

class Note(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notes")
    title = models.CharField(max_length=255)
    serialized_content = models.TextField()
    likes = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='note_like')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def number_of_likes(self):
        return self.likes.count()
    
    def __str__(self):
        return self.title
