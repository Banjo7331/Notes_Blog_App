from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import JsonResponse
from account.models import Follow
from .models import Note
from .forms import MarkdownNoteForm
from notes_keeping_site.forms import OTPForm  
from .utils import sanitize_markdown, encrypt, decrypt
from notes_keeping_site.utils import decrypt_otp_secret, sign_note, verify_signature, evaluate_password_strength
from django.db.models import Count
import pyotp
import re


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
                recipient_usernames = form.cleaned_data['recipient_usernames']
                note_password = form.cleaned_data['password']

                sanitized_html = sanitize_markdown(raw_content)

                if is_private:
                    if not note_password:
                        messages.error(request, "Password cant be empty if you want make a private note")
                        return redirect('profile', username=username)

                    password_strength, password_message = evaluate_password_strength(note_password)

                    if password_strength == "very_weak":
                        messages.error(request, f"Password is too weak")
                        return redirect('profile', username=username)
                    
                    if not re.match(r'^[a-zA-Z0-9, ]+$', recipient_usernames):
                        messages.error(request, f"One or more recipients not found")
                        return redirect('profile', username=username)

                    usernames = [username.strip() for username in recipient_usernames.split(",")]

                    recipients = list(NoteSiteUser.objects.filter(username__in=usernames))

                    if not recipients:
                        messages.error(request, "Private notes must have at least one recipient.")
                        return redirect('profile', username=username)

                    found_usernames = set(user.username for user in recipients)
                    invalid_usernames = [u for u in usernames if u not in found_usernames]

                    if invalid_usernames:
                        messages.error(request, f"One or more recipients not found")
                        return redirect('profile', username=username)
                    
                    sanitized_html = encrypt(sanitized_html, note_password)

                   
                signature = sign_note(request.user, sanitized_html)

                new_note = Note.objects.create(
                    author=request.user,
                    title=title,
                    serialized_content=sanitized_html,
                    signature=signature,
                    is_private=is_private
                )
                if is_private and recipients:
                    new_note.recipients.set(recipients)

                return redirect('profile', username=username)
        else:
            form = MarkdownNoteForm() 

    elif is_owner and not is_obligated:
            
        if request.method == 'POST':
            form = OTPForm(request.POST)

            if form.is_valid():
                otp_code = form.cleaned_data["otp_code"]\
            
                user = request.user
                otp_secret = user.otp_secret
                
                decrypted_otp_secret = decrypt_otp_secret(otp_secret)
                
                totp = pyotp.TOTP(decrypted_otp_secret)
                
                if totp.verify(otp_code, valid_window=1):
                    user.is_key_enabled = True
                    user.save()
                    messages.success(request, 'OTP verified. You can now make notes.')
                    return redirect('profile', username=username)
                else:
                    messages.error(request, 'Invalid OTP. Please try again.')
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
    received_notes = Note.objects.filter(is_private=True, recipients=user).order_by('-created_at')

    paginator = Paginator(received_notes, 7)  
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    return render(request, 'notes/sent_notes_box.html', {'page_obj': page_obj})

@login_required
def decrypt_note(request, note_id):
    if request.method == "POST":
        password = request.POST.get("password")
        if not password:
            return JsonResponse({"error": "You need to write password."}, status=400)

        note = Note.objects.filter(id=note_id, recipients=request.user, is_private=True).first()
        if not note:
            return JsonResponse({"error": "Note is not existig or you have no obligations to it."}, status=404)

        try:
            decrypted_content = decrypt(note.serialized_content, password)
            return JsonResponse({"content": decrypted_content})
        except Exception as e:
            return JsonResponse({"error": f"❌ Encryption error: {str(e)}"}, status=400)

    return JsonResponse({"error": "Nieprawidłowa metoda żądania."}, status=405)

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