from django.urls import path
from .views import VerifyOtp ,VerifyEmailView, UserLogin, SignUp, DeleteUsers

urlpatterns = [
    path("login/", UserLogin.as_view(), name="login"),
    path("sign-up/", SignUp.as_view(), name="login"),
    path('verify-mail/', VerifyEmailView.as_view()),
    path('verify-otp/', VerifyOtp.as_view()),
    path('delete/', DeleteUsers.as_view()),
    

]