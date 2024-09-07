from typing import Any
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework import status

class LoginUtils:
    @staticmethod
    def credentials_login(request) -> tuple[dict, Any]:
        try:
            email = username = request.data.get("email")
            password = request.data.get("password")
            _user = authenticate(
                request,
                username=username,
                password=password
            )
            if not _user:
                return (
                    {"message": "Invalid email or password"},
                    status.HTTP_403_FORBIDDEN
                )

            # _token, first_login = Token.objects.get_or_create(user_id=_user.id)
            # _user.last_login = timezone.now()
            # _user.save()
            return (
                {
                    "message": "Login Successful",
                    "email": _user.username,
                    # "access_token": _token.key,
                    # "coin_popup": first_login
                },
                status.HTTP_200_OK
            )
        except Exception as e:
            return ({"message": str(e)}, status.HTTP_408_REQUEST_TIMEOUT)

    # @staticmethod
    # def google_auth_login(username) -> tuple[dict, Any]:
    #     try:
    #         # Get or create the user in your system
    #         _user, created = User.objects.get_or_create(username=username)

    #         _token, _ = Token.objects.get_or_create(user_id=_user.id)
    #         _user.last_login = timezone.now()
    #         _user.save()
    #         return (
    #             {
    #                 "message": "Token verification successful",
    #                 "email": _user.username,
    #                 "access_token": str(_token.key),
    #                 "coin_popup": created or _
    #             },
    #             status.HTTP_200_OK,
    #         )
    #     except Exception as e:
    #         return (
    #             {"message": str(e)}, status.HTTP_400_BAD_REQUEST
    #         )
