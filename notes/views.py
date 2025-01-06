import base64
import os
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.http import JsonResponse

from account.models import Follow
from .models import Note
from .forms import MarkdownNoteForm, PublicKeyUploadForm
from .utils import sanitize_markdown, encrypt_content, decrypt_content
from django.db.models import Count

NoteSiteUser = get_user_model()

@login_required
def LikeView(request, note_id):
    note = get_object_or_404(Note, id=note_id)
    if note.likes.filter(id=request.user.id).exists():
        note.likes.remove(request.user)
    else:
        note.likes.add(request.user)
    return redirect('profile', username=note.user.username)

@login_required
def FallowView(request, user_id):
    user = get_object_or_404(NoteSiteUser, id=user_id)
    if user == request.user:
        messages.error(request, "You cannot follow yourself!")
        return redirect('profile', username=user.username)

    follow_relationship = Follow.objects.filter(follower=request.user, following=user)

    if follow_relationship.exists():
        follow_relationship.delete()
        messages.success(request, f"You have unfollowed {user.username}.")
    else:
        Follow.objects.create(follower=request.user, following=user)
        messages.success(request, f"You are now following {user.username}.")

    return redirect('profile', username=user.username)

@login_required
def profile_view(request, username):

    profile_user = get_object_or_404(NoteSiteUser, username=username)

    is_following = Follow.objects.filter(follower=request.user, following=profile_user).exists() if request.user.is_authenticated else False
    print(is_following)
    user_notes = Note.objects.filter(author=profile_user).order_by('-created_at')

    is_obligated = request.user.is_key_enabled
    is_owner = request.user.is_authenticated and profile_user == request.user
    
    if is_owner and is_obligated:
        if request.method == "POST":
            form = MarkdownNoteForm(request.POST)
            if form.is_valid():
                title = form.cleaned_data['title']
                raw_content = form.cleaned_data['content']

                is_private = form.cleaned_data['is_private']
                recipient_username = form.cleaned_data['recipient_username']
                print("POST data:", request.POST)
                recipient = None
                if is_private:
                    if recipient_username:
                        recipient = get_object_or_404(NoteSiteUser, username=recipient_username)
                    else:
                        return JsonResponse({"error": "Recipient username is required for private notes"}, status=400)

                sanitized_html = sanitize_markdown(raw_content)

                aes_key = None
                if is_private:
                    sanitized_html = encrypt_content(sanitized_html, recipient.public_key)

                Note.objects.create(
                    author=request.user,
                    title=title,
                    serialized_content=sanitized_html,
                    is_private=is_private,
                    recipient=recipient
                )

                if is_private and aes_key:
                    return JsonResponse({
                        "message": "Note created successfully",
                        "aes_key": base64.b64encode(aes_key).decode()
                    })

                return redirect('profile', username=username)
        else:
            form = MarkdownNoteForm() 

    elif is_owner and not is_obligated:
        if request.method == 'POST':
            form = PublicKeyUploadForm(request.POST)
            if form.is_valid():
                public_key = form.cleaned_data['content']
                
                try:
                    from cryptography.hazmat.primitives.serialization import load_pem_public_key
                    load_pem_public_key(public_key.encode())
                except Exception:
                    return JsonResponse({"error": "Invalid public key format."}, status=400)
                
                user = request.user
                user.public_key = public_key
                user.is_key_enabled = True
                user.save()
                messages.success(request, 'You can now make notes.')
                return redirect('profile', username=username)
        else:
            form = PublicKeyUploadForm()
    else:
        form =  None

    page_number = request.GET.get('page', 1)
    paginator = Paginator(user_notes, 7)
    page_obj = paginator.get_page(page_number)

    return render(request, 'notes/profile.html', {
        'profile_user': profile_user,
        'page_obj': page_obj,
        'is_owner': is_owner,
        'is_obligated': is_obligated,
        'is_following': is_following,
        'form': form,
    })

@login_required
def sent_notes_box(request):
    user = request.user
    sent_notes = Note.objects.filter(recipient=user).order_by('-created_at')

    page_number = request.GET.get('page', 1)
    paginator = Paginator(sent_notes, 7)
    page_obj = paginator.get_page(page_number)

    decrypted_message = None

    if request.method == 'POST':
        note_id = request.POST.get('note_id')
        private_key = request.POST.get('private_key')
        print("test")
        try:
            note = Note.objects.get(id=note_id, recipient=user)
            print("is there any?")
            decrypted_message = decrypt_content(note.serialized_content, private_key)
            print(decrypted_message, "is there any?")
        except Exception as e:
            print("fak")
            messages.error(request, f"Decryption failed: {str(e)}")

    return render(request, 'notes/sent_notes_box.html',  {'decrypted_message': decrypted_message,'page_obj': page_obj})

@login_required
def dashboard(request):
    user = request.user

    notes = Note.objects.annotate(like_count=Count('likes')).order_by('-like_count', '-created_at')
    
    if Follow.objects.filter(follower=user).exists():
        follower_notes = Note.objects.filter(
            user__in=Follow.objects.filter(follower=user).values_list('following', flat=True)
        ).annotate(
            like_count=Count('likes')
        ).order_by('-created_at')

        notes = notes | follower_notes

    page_number = request.GET.get('page', 1)
    paginator = Paginator(notes, 7)
    page_obj = paginator.get_page(page_number)

    return render(request, 'notes/dashboard.html', {'section': 'dashboard', 'page_obj': page_obj})