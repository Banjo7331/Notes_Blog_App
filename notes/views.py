from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required

from account.models import Follow
from .models import Note
from .forms import MarkdownNoteForm
from .utils import sanitize_markdown
from django.db.models import Count

NoteSiteUser = get_user_model()

def LikeView(request, note_id):
    note = get_object_or_404(Note, id=note_id)
    if note.likes.filter(id=request.user.id).exists():
        note.likes.remove(request.user)
    else:
        note.likes.add(request.user)
    return redirect('profile', username=note.user.username)

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
    user_notes = Note.objects.filter(user=profile_user).order_by('-created_at')

    is_owner = request.user.is_authenticated and profile_user == request.user

    if is_owner and request.method == "POST":
        form = MarkdownNoteForm(request.POST)
        if form.is_valid():
            title = form.cleaned_data['title']
            raw_content = form.cleaned_data['content']

            sanitized_html = sanitize_markdown(raw_content)

            Note.objects.create(
                user=request.user,
                title=title,
                serialized_content=sanitized_html
            )

            return redirect('profile', username=username)
    else:
        form = MarkdownNoteForm() if is_owner else None

    return render(request, 'notes/profile.html', {
        'profile_user': profile_user,
        'notes': user_notes,
        'is_owner': is_owner,
        'is_following': is_following,
        'form': form,
    })


@login_required
def dashboard(request):
    user = request.user
    notes = Note.objects.annotate(like_count=Count('likes')).order_by('-like_count', '-created_at')
    
    if Follow.objects.filter(follower=user).exists():
        notes = Note.objects.filter(
            user__in=Follow.objects.filter(follower=user).values_list('following', flat=True)
        ).annotate(
            like_count=Count('likes')
        ).order_by('-created_at')

    return render(request, 'notes/dashboard.html', {'section': 'dashboard', 'notes': notes})