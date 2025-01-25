from django import forms
from django.contrib.auth import get_user_model

class MarkdownNoteForm(forms.Form):
    title = forms.CharField(
        required=True,
        max_length=15,
        widget=forms.TextInput(attrs={'placeholder': 'Enter note title'})
    )
    content = forms.CharField(
        max_length=200,
        widget=forms.Textarea(attrs={'rows': 10, 'placeholder': 'Write your Markdown note here...'}),
        required=True
    )
    is_private = forms.BooleanField(
        required=False,
        initial=False,
        label="Private",
        help_text="Check to make this note private"
    )
    recipient_usernames = forms.CharField(
        required=False,
        label="Recipients",
        help_text="Enter multiple usernames separated by commas",
        widget=forms.TextInput(attrs={'placeholder': 'e.g., user1, user2, user3'})
    )
    password = forms.CharField(
        max_length=15,
        required=False,
        widget=forms.PasswordInput(attrs={'placeholder': 'Enter encryption password'}),
        help_text="If set, this password will encrypt your note."
    )

class OTPForm(forms.Form):
    otp_code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'placeholder': 'Enter 6-digit OTP',
            'pattern': '[0-9]{6}',  # Wymusza 6 cyfr
            'title': '6-digit code required'
        }),
        required=True,
        label="OTP Code"
    )