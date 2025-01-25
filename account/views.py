from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, get_user_model
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from account.models import NoteSiteUser
from .forms import LoginForm, UserRegistrationForm
from django.contrib.auth.views import LoginView
from axes.handlers.proxy import AxesProxyHandler
from django.contrib import messages
import pyotp
import time
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.http import urlsafe_base64_decode
from account.utils import email_verification, generate_qr_code
from notes_keeping_site.utils import encrypt_otp_secret, decrypt_otp_secret, evaluate_password_strength
from django.utils.encoding import force_str
from account.tokens import account_activation_token
import uuid

def user_login(request):
    storage = messages.get_messages(request)
    storage.used = True
    
    if AxesProxyHandler.is_locked(request):
        messages.error(request, 'Account locked: too many login attempts. Please try again later.')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            cd = form.cleaned_data
            time.sleep(2)
            user = authenticate(request, username=cd['username'], password=cd['password'])
            if user is not None:
                if user.is_active:
                    request.session['temp_user_id'] = str(user.id)

                    return redirect('verify_otp') 
                else:
                    return HttpResponse('Disabled account')
            else:
                messages.error(request, 'Invalid username or password.')
                return redirect('login')  
    else:
        form = LoginForm()

    return render(request, 'registration/login.html', {'form': form})  

def register(request):
    if request.method == 'POST':
        user_form = UserRegistrationForm(request.POST)
        if user_form.is_valid():
            password = user_form.cleaned_data['password']

            password_strength, password_message = evaluate_password_strength(password)

            try:
                validate_password(password)
            except ValidationError as e:
                user_form.add_error('password', e)
                return render(request, 'registration/register.html', {
                    'user_form': user_form,
                    'password_strength': password_strength,
                    'password_message': password_message,
                })
            
            if password_strength == "very_weak":
                user_form.add_error('password', "Password is too weak.")
                return render(request, 'registration/register.html', {
                    'user_form': user_form,
                    'password_strength': password_strength,
                    'password_message': password_message,
                })

            otp_secret = pyotp.random_base32()
            encrypted_otp_secret = encrypt_otp_secret(otp_secret)
            print(f"Encrypted secret before saving: {encrypted_otp_secret}")

            new_user = user_form.save(commit=False)
            new_user.set_password(user_form.cleaned_data["password"])
            new_user.otp_secret = encrypted_otp_secret
            new_user.is_active = False

            new_user.save()

            user_from_db = NoteSiteUser.objects.get(id=new_user.id)
            print(f"Encrypted secret after saving: {user_from_db.otp_secret}")

            email_verification(request, new_user, user_form.cleaned_data.get('email'))

            return render(request,'registration/register_done.html',{'new_user':new_user})

    else:
        user_form = UserRegistrationForm()
    return render(request,
                  'registration/register.html',
                  {'user_form': user_form})

def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'You are verified! Now you can login.')
    else:
        messages.error(request, 'Activation link is invalid!')

    return redirect('login')

NoteSiteUser = get_user_model()

def verify_otp(request):

    if 'temp_user_id' not in request.session:
        return redirect('login') 
    
    user_id = request.session['temp_user_id']
    user = NoteSiteUser.objects.get(id=uuid.UUID(user_id))

    qrcode = None
    if not user.is_2fa_enabled:
        if(user.otp_secret == None):
            otp_secret = pyotp.random_base32()
            user.otp_secret = encrypt_otp_secret(otp_secret)
            user.save()
        qrcode = generate_qr_code(user)

    if request.method == 'POST':
        otp_code = request.POST.get('otp_code')
        
        
        otp_secret = user.otp_secret
        decrypted_otp_secret = decrypt_otp_secret(otp_secret)
        print(f"OTP Secret: {decrypted_otp_secret}")
        
        totp = pyotp.TOTP(decrypted_otp_secret)

        expected_otp = totp.now()
        print(f"Expected OTP: {expected_otp}, Provided OTP: {otp_code}")

        if totp.verify(otp_code,valid_window=1):
            if not user.is_2fa_enabled:
                user.is_2fa_enabled = True
                user.save()
            del request.session['temp_user_id']
            login(request, user,backend='django.contrib.auth.backends.ModelBackend')
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid OTP. Please try again.')

    return render(request, 'registration/otp.html', {
        'qrcode': qrcode,
        'email': user.email,
    })



