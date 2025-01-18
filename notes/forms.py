from django import forms
from django.contrib.auth import get_user_model

class MarkdownNoteForm(forms.Form):
    title = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={'placeholder': 'Enter note title'})
    )
    content = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 10, 'placeholder': 'Write your Markdown note here...'}),
        required=True
    )
    is_private = forms.BooleanField(
        required=False,
        initial=False,
        label="Private",
        help_text="Check to make this note private"
    )
    recipient_username = forms.CharField(
        required=False,
        max_length=20,
        label="Recipient (username, if private)",
        help_text="Enter the username of the user to share this note with",
        widget=forms.TextInput(attrs={'class': 'hidden'})
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