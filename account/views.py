from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, get_user_model
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from account.models import NoteSiteUser
from account.utils import send_otp
from .forms import LoginForm, UserRegistrationForm
from django.contrib.auth.views import LoginView
from axes.handlers.proxy import AxesProxyHandler
from django.contrib import messages
import pyotp
import io
import qrcode
from datetime import datetime
import base64


class OTPLoginView(LoginView):
    def form_valid(self, form):
        print("siema"+AxesProxyHandler.is_locked(self.request))
        if AxesProxyHandler.is_locked(self.request):
            messages.error(self.request, 'Account locked: too many login attempts. Please try again later.')
            return redirect('login') 
        
        username = form.cleaned_data.get('username')
        password = form.cleaned_data.get('password')
        user = authenticate(self.request, username=username, password=password)

        if user is not None:
            self.request.session['temp_user_id'] = user.id
            print(f"2FA Enabled: {getattr(user, 'is_2fa_enabled', True)}")
            if user.is_2fa_enabled: 
                self.request.session['temp_user_id'] = user.id
                return redirect('verify_otp')
            login(self.request, user)
            return redirect('dashboard')
        else:
            messages.error(self.request, 'Invalid username or password.')
            return redirect('login')

def register(request):
    if request.method == 'POST':
        user_form = UserRegistrationForm(request.POST)
        if user_form.is_valid():
            otp_secret = pyotp.random_base32()

            request.session['temp_user_data'] = {
                'username': user_form.cleaned_data['username'],
                'email': user_form.cleaned_data['email'],
                'password': user_form.cleaned_data['password'],
                'otp_secret': otp_secret,
            }

            return redirect(reverse('setup_otp'))

    else:
        user_form = UserRegistrationForm()
    return render(request,
                  'registration/register.html',
                  {'user_form': user_form})

def setup_otp(request):
    user_data = None
    user_email = None
    if request.user:
        user_data = request.user
        user_email = user_data.email
        otp_secret = pyotp.random_base32()
        user_data.otp_secret = otp_secret

        if request.method == 'POST':
            otp = request.POST.get('otp')
            totp = pyotp.TOTP(user_data.otp_secret)
            if totp.verify(otp,valid_window=1):
                user_data.is_2fa_enabled = True
                user_data.save()
                return redirect('dashboard')
    else:
        user_data = request.session.get('temp_user_data')
        user_email = user_data['email']
        if not user_data:
            return redirect('register')

        if request.method == 'POST':
            otp = request.POST.get('otp')
            totp = pyotp.TOTP(user_data['otp_secret'])
            if totp.verify(otp,valid_window=1):
                
                new_user = NoteSiteUser(
                    username=user_data['username'],
                    email=user_data['email'],
                    otp_secret=user_data['otp_secret'],
                    is_2fa_enabled=True
                )
                new_user.set_password(user_data['password'])
                new_user.save()

                del request.session['temp_user_data']
                login(request, new_user)
                return redirect('dashboard')
            else:
                return render(request, 'registration/setup_otp.html', {
                    'qrcode': generate_qr_code(user_data),
                    'email': user_data['email'],
                    'error': 'Invalid OTP. Please try again.',
                })

    return render(request, 'registration/setup_otp.html', {
        'qrcode': generate_qr_code(user_data),
        'email': user_email,
    })

NoteSiteUser = get_user_model()

def verify_otp(request):
    if 'temp_user_id' not in request.session:
        return redirect('login') 

    user_id = request.session['temp_user_id']
    user = NoteSiteUser.objects.get(id=user_id)

    if request.method == 'POST':
        otp_code = request.POST.get('otp_code')
        otp_secret = user.otp_secret
        print(f"OTP Secret: {otp_secret}")
        
        totp = pyotp.TOTP(otp_secret)

        expected_otp = totp.now()
        print(f"Expected OTP: {expected_otp}, Provided OTP: {otp_code}")

        if totp.verify(otp_code):
            del request.session['temp_user_id']
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid OTP. Please try again.')


    return render(request, 'registration/otp.html', {'user': user})

def generate_qr_code(temp_user_data):
    otp_secret = temp_user_data['otp_secret']
    otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
        name=temp_user_data['email'],
        issuer_name="NOTES_APP"
    )

    qr = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    qr_code = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{qr_code}"
