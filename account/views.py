from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, get_user_model
from django.contrib.auth.decorators import login_required
from account.utils import send_otp
from .forms import LoginForm
from django.contrib.auth.views import LoginView
from django.contrib import messages
import pyotp
from datetime import datetime


# Create your views here.
# def user_login(request):
#     if request.method == 'POST':
#         form = LoginForm(request.POST)
#         if form.is_valid():
#             cd = form.cleaned_data
#             user = authenticate(request, username=cd['username'], password=cd['password'])
#             if user is not None:
#                 if user.is_active:
#                     login(request, user)
#                 else:
#                     return HttpResponse('Disabled account')
#             else:
#                 return HttpResponse('Invalid login')
#     else:
#         form = LoginForm()
#     return render(request, 'account/login.html', {'form': form})

class OTPLoginView(LoginView):
    def form_valid(self, form):
        username = form.cleaned_data.get('username')
        password = form.cleaned_data.get('password')
        user = authenticate(self.request, username=username, password=password)

        if user:
            self.request.session['temp_user_id'] = user.id
            print(f"2FA Enabled: {getattr(user, 'is_2fa_enabled', True)}")
            if getattr(user, 'is_2fa_enabled', True): 
                send_otp(self.request) 
                print("OTP sent successfully")
                return redirect('otp')
            print(f'{user.is_authenticated}')
            login(self.request, user)
            return redirect('dashboard')
        else:
            messages.error(self.request, 'Invalid username or password.')
            return redirect('login')
        
User = get_user_model()

def otp_view(request):

    if 'temp_user_id' not in request.session:
        return redirect('login') 

    user_id = request.session['temp_user_id']
    user = User.objects.get(id=user_id)

    if request.method == 'POST':
        otp_code = request.POST.get('otp_code')
        otp_secret = request.session.get('otp_secret_key')
        otp_valid_date = request.session.get('otp_valid_date')

        if not otp_valid_date or datetime.now() > datetime.fromisoformat(otp_valid_date):
            messages.error(request, 'OTP has expired. Please try logging in again.')
            return redirect('login')

        totp = pyotp.TOTP(otp_secret, interval=60)
        if totp.verify(otp_code):
            login(request, user)
            del request.session['temp_user_id']
            del request.session['otp_secret_key']
            del request.session['otp_valid_date']
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid OTP. Please try again.')


    return render(request, 'registration/otp.html', {'user': user})
