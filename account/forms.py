from django import forms
from django.contrib.auth import get_user_model
import re

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

    honeypot = forms.CharField(
        required=False,
        widget=forms.HiddenInput(),
    )

    def clean_honeypot(self):
        if self.cleaned_data.get("honeypot"):
            raise forms.ValidationError("Invalid login data.")
    
class UserRegistrationForm(forms.ModelForm):
    username = forms.CharField(min_length=3,    
                               max_length=20,  
    )
    password = forms.CharField(min_length=10,
                               label ='Password',
                               widget=forms.PasswordInput)
    passwordRepeat = forms.CharField(label ='Repeat password',
                               widget=forms.PasswordInput)
    
    class Meta:
        model = get_user_model()
        fields = ('username', 'email')
    def clean_username(self):
        username = self.cleaned_data.get('username')
        
        if not re.match(r'^[a-zA-Z0-9]+$', username):
            raise forms.ValidationError("Username can only contain letters and numbers.")
        
        return username
    
    def clean_passwordRepeat(self):
        cd = self.cleaned_data
        if cd['password'] != cd['passwordRepeat']:
            raise forms.ValidationError('Passwords do not match.')
        return cd['passwordRepeat']
