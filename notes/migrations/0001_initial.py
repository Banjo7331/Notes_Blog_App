# Generated by Django 5.1.4 on 2025-01-24 23:44

import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Note',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('is_private', models.BooleanField(default=False)),
                ('title', models.CharField(max_length=255)),
                ('serialized_content', models.TextField()),
                ('signature', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notes', to=settings.AUTH_USER_MODEL)),
                ('likes', models.ManyToManyField(related_name='note_like', to=settings.AUTH_USER_MODEL)),
                ('recipients', models.ManyToManyField(blank=True, related_name='received_notes', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
