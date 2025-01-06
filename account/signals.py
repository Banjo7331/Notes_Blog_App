from django.core.mail import send_mail
from axes.signals import user_locked_out
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.utils.timezone import now
from django.contrib.auth.signals import user_logged_in
from .models import LoginIP

NoteSiteUser = get_user_model()

@receiver(user_locked_out)
def send_lockout_email(sender, request, username, **kwargs):
    try:
        user = NoteSiteUser.objects.get(username=username)
        user_email = user.email
    except NoteSiteUser.DoesNotExist:
        user_email = None  

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

    is_new_ip = not LoginIP.objects.filter(user=user, ip_address=ip_address).exists()

    if user_email:
        subject = "Alert: Twoje konto zostało tymczasowo zablokowane"
        new_ip_message = ""
        if is_new_ip:
            new_ip_message =  f"Blokada została wywołana z nowego adresu IP, który nie był wcześniej używany do logowania!\n\n"

        message = (
            f"Wykryliśmy zablokowanie Twojego konta z powodu wielokrotnych nieudanych prób logowania.\n\n"
            f"Data: {now()}\n"+
            new_ip_message+
            f"Jeśli to Ty próbowałeś się zalogować i napotkałeś problem, skontaktuj się z administratorem lub spróbuj ponownie później.\n"
            f"Jeśli nie rozpoznajesz tej aktywności, zalecamy natychmiastową zmianę hasła, gdy blokada zostanie zdjęta."
        )
        send_mail(
            subject,
            message,
            None,
            [user_email],
            fail_silently=False,
        )

@receiver(user_logged_in)
def save_login_ip(sender, request, user, **kwargs):

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    ip = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

    if not LoginIP.objects.filter(user=user, ip_address=ip).exists():
        LoginIP.objects.create(user=user, ip_address=ip)