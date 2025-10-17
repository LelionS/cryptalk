import random
from django.core.mail import send_mail
from django.utils import timezone

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_via_email(email, otp):
    subject = "Verify your Email - Chat System"
    message = f"Your verification code is {otp}. It will expire in 10 minutes."
    from_email = "no-reply@chatapp.local"
    send_mail(subject, message, from_email, [email], fail_silently=False)
