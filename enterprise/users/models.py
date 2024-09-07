from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.

class OTPModel(models.Model):
    user_email = models.EmailField(max_length = 255, unique = True)
    latest_otp = models.CharField(max_length = 4)