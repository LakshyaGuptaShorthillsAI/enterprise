from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import VerifyEmailSerializer
from rest_framework import status
from .logic_source.UserLoginManage import LoginUtils
from .logic_source.UserSignupManage import SignupUtils
from .models import OTPModel
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.http import Http404

class VerifyEmailView(APIView):
    
    def post(self, request):
        try:
            user_email = request.data.get('email')
            serializer = VerifyEmailSerializer(data={"email" : user_email})
            serializer.is_valid(raise_exception=True)
            otp_error = SignupUtils.send_otp(user_email)
            if otp_error:
                raise Exception('Could not send the otp code')
            return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(data={"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
class VerifyOtp(APIView):
    
    def post(self, request):
        try:
            email = request.data.get('email')
            otp = request.data.get('otp')
            otp_entry = get_object_or_404(OTPModel, user_email = email)
            if otp_entry.latest_otp == otp:
                return Response({'message': 'OTP verification successful'}, status=status.HTTP_200_OK)

            return Response({'message': 'OTP invalid/expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except Http404:
            return Response({'message': 'Otp entry does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'message': 'OTP verification failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
class SignUp(APIView):
    # pass
    def post(self, request):
        try:
            username = email = request.data.get('email')
            password = request.data.get('password')
            user = User.objects.create(username = username, email = email)
            user.set_password(password)
            user.save()
            return Response({'message': "User created successfully"}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response(data={"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
class UserLogin(APIView, LoginUtils):
    def post(self, request):
        try:
            res, res_status = self.credentials_login(request=request)
            return Response(res, status=res_status)
        except Exception as e:
            return Response(
                {"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
class DeleteUsers(APIView):
    def get(self, request):
        users = User.objects.raw('Select * from auth_user')
        for user in users:
            user.delete()
        return Response("All users deleted")
