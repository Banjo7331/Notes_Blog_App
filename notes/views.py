import base64
import os
from collections import namedtuple
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.http import JsonResponse

from account.models import Follow
from .models import Note
from .forms import MarkdownNoteForm, OTPForm
from .utils import sanitize_markdown, encrypt, decrypt
from notes_keeping_site.utils import decrypt_otp_secret, generate_rsa_key_pair_for_user, get_private_key, sign_note, verify_signature
from django.db.models import Count
import pyotp

NoteSiteUser = get_user_model()

@login_required
def LikeView(request, note_id):
    note = get_object_or_404(Note, id=note_id)
    if note.likes.filter(id=request.user.id).exists():
        note.likes.remove(request.user)
    else:
        note.likes.add(request.user)
    return redirect('profile', username=note.author.username)

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
    user_notes = Note.objects.filter(author=profile_user,is_private=False).order_by('-created_at')

    verified_notes = [note for note in user_notes if verify_signature(note.author, note.serialized_content, note.signature)]

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
                    sanitized_html = encrypt(sanitized_html, recipient.public_key)

                signature = sign_note(request.user, sanitized_html)

                Note.objects.create(
                    author=request.user,
                    title=title,
                    serialized_content=sanitized_html,
                    signature=signature,
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
            otp_code = request.POST.get('otp_code')
            
            user = request.user
            otp_secret = user.otp_secret
            
            decrypted_otp_secret = decrypt_otp_secret(otp_secret)
            print(f"OTP Secret: {decrypted_otp_secret}")
            
            totp = pyotp.TOTP(decrypted_otp_secret)
            
            if totp.verify(otp_code, valid_window=1):
                generate_rsa_key_pair_for_user(user)
                user.is_key_enabled = True
                user.save()
                messages.success(request, 'OTP verified. You can now make notes.')
                return redirect('profile', username=username)
            else:
                return JsonResponse({"error": "Invalid OTP code."}, status=400)
        else:
            form = OTPForm() 
    else:
        form = None

    page_number = request.GET.get('page', 1)
    paginator = Paginator(verified_notes, 7)
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
    sent_notes = Note.objects.filter(is_private=True,recipient=user).order_by('-created_at')
    verified_notes = [note for note in sent_notes if verify_signature(note.author, note.serialized_content, note.signature)]
    print(len(verified_notes))
    private_key = get_private_key(user.id)

    DecryptedNote = namedtuple('DecryptedNote', ['author', 'title', 'created_at', 'content'])

    decrypted_notes = []
    for note in verified_notes:
        try:
            decrypted_content = decrypt(note.serialized_content, private_key) if private_key else "🔒 No private key found"
        except Exception as e:
            decrypted_content = f"❌ Decryption error: {str(e)}"
        
        temp_note = DecryptedNote(
            title=note.title, 
            created_at=note.created_at, 
            author=note.author.username if note.author else "Unknown Sender",
            content=decrypted_content
        )
        decrypted_notes.append(temp_note)

    page_number = request.GET.get('page', 1)
    paginator = Paginator(decrypted_notes, 7)  
    page_obj = paginator.get_page(page_number)

    return render(request, 'notes/sent_notes_box.html', {'page_obj': page_obj})

@login_required
def dashboard(request):
    user = request.user

    notes = Note.objects.filter(is_private=False).annotate(like_count=Count('likes')).order_by('-like_count', '-created_at')
    verified_notes = [note for note in notes if verify_signature(note.author, note.serialized_content, note.signature)]

    if verified_notes:
        verified_notes = Note.objects.filter(id__in=[note.id for note in verified_notes])
    else:
        verified_notes = Note.objects.none()

    if Follow.objects.filter(follower=user).exists():
        follower_notes = Note.objects.filter(
            is_private=False,
            author__in=Follow.objects.filter(follower=user).values_list('following', flat=True)
        ).annotate(
            like_count=Count('likes')
        ).order_by('-created_at')

        verified_notes = verified_notes | follower_notes

    page_number = request.GET.get('page', 1)
    paginator = Paginator(verified_notes, 7)
    page_obj = paginator.get_page(page_number)

    return render(request, 'notes/dashboard.html', {'section': 'dashboard', 'page_obj': page_obj})