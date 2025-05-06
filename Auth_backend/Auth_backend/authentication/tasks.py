from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags

@shared_task
def send_verification_email(user_email, verification_url):
    subject = 'Verify your email address'
    html_message = render_to_string('authentication/email/verify_email.html', {
        'verification_url': verification_url
    })
    plain_message = strip_tags(html_message)
    
    return send_mail(
        subject=subject,
        message=plain_message,
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[user_email],
        html_message=html_message,
        fail_silently=False,
    )

@shared_task
def send_password_reset_email(user_email, reset_url):
    subject = 'Reset your password'
    html_message = render_to_string('authentication/email/reset_password.html', {
        'reset_url': reset_url
    })
    plain_message = strip_tags(html_message)
    
    return send_mail(
        subject=subject,
        message=plain_message,
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[user_email],
        html_message=html_message,
        fail_silently=False,
    )