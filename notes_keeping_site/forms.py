from django import forms

class OTPForm(forms.Form):
    otp_code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'placeholder': 'Enter 6-digit OTP',
            'pattern': '[0-9]{6}', 
            'title': '6-digit code required'
        }),
        required=True,
        label="OTP Code"
    )

    def clean_otp_code(self):
        otp = self.cleaned_data["otp_code"]

        if not otp.isdigit():
            raise forms.ValidationError("OTP must contain only digits.")

        return otp 