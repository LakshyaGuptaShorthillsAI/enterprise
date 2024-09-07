from django.core.mail import send_mail
import random
from users.models import OTPModel

class SignupUtils:
    @staticmethod
    def send_otp(email):
        try:
            otp = random.randint(1000,9999)
            otp_entry, created = OTPModel.objects.get_or_create(user_email=email)
            while int(otp_entry.latest_otp) == int(otp):
                otp = random.randint(1000,9999)
            send_mail(subject="Verify email for Enterprise",message=f'Your otp code is {otp}', from_email='smtp.gmail.com', recipient_list=[email])
            otp_entry.latest_otp = otp
            otp_entry.save()
        except Exception as e:
            print(e)
            return ConnectionError('Failed to send the otp. Please retry')
