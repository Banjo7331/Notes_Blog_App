from django.core.mail import send_mail
from axes.signals import user_locked_out
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.utils.timezone import now
from django.contrib.auth.signals import user_logged_in
from .models import LoginIP

NoteSiteUser = get_user_model()

def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip

def send_lockout_email(sender, request, username, **kwargs):
    try:
        user = NoteSiteUser.objects.get(username=username)
        user_email = user.email
    except NoteSiteUser.DoesNotExist:
        user_email = None
        user = None 

    ip_address = get_client_ip(request)

    is_new_ip = False
    if user:
        is_new_ip = not LoginIP.objects.filter(user=user, ip_address=ip_address).exists()

    if user_email:
        subject = "Your Account Has Been Temporarily Locked"
        new_ip_message = ""
        if is_new_ip:
            new_ip_message = (
                "This lockout was triggered from a NEW IP address that has never been used before!\n\n"
            )

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
    ip = get_client_ip(request)

    if not LoginIP.objects.filter(user=user, ip_address=ip).exists():
        LoginIP.objects.create(user=user, ip_address=ip)