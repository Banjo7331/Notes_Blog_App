from django import forms
from django.contrib.auth import get_user_model

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)
    
class UserRegistrationForm(forms.ModelForm):
    password = forms.CharField(min_length=10,
                               label ='Password',
                               widget=forms.PasswordInput)
    passwordRepeat = forms.CharField(label ='Repeat password',
                               widget=forms.PasswordInput)
    
    class Meta:
        model = get_user_model()
        fields = ('username', 'email')
    
    def clean_passwordRepeat(self):
        cd = self.cleaned_data
        if cd['password'] != cd['passwordRepeat']:
            raise forms.ValidationError('Passwords do not match.')
        return cd['passwordRepeat']
