# from AIStudioEnterprise.settings import (
#     STORAGE_ACCOUNT_ACCESS_KEY,
#     STORAGE_ACCOUNT_NAME,
#     CONTAINER_NAME,
#     SIMPLE_JWT,
#     WEAVIATE_URL_INSTANCE,
#     WEAVIATE_API_KEY,
#     FIELD_ENCRYPTION_KEY,
#     READ_URL_EXP_DAYS,
# )
# from azure.storage.blob import (
#     BlobServiceClient,
#     BlobClient,
# )
from django.utils import timezone
from rest_framework import status
# import jwt
import re
from django.core.mail import EmailMessage
from django.conf import settings
from django.template.loader import render_to_string
from email.mime.image import MIMEImage
from datetime import datetime, timedelta
# from cryptography.fernet import Fernet
# from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
# import weaviate


class Utils:

    @staticmethod
    def send_email(data):
        try:
            message = render_to_string(data['email_html'], {
                'verification_link': data['verification_link']
            })
            email = EmailMessage(
                subject=data['subject'],
                body=message,
                from_email=settings.EMAIL_HOST_USER,
                to=[data['to_email']]
            )
            email.content_subtype = 'html'

            image_path = 'users/static/users/images/logo.png'
            image = 'logo.png'

            with open(image_path, 'rb') as f:
                img = MIMEImage(f.read())
                img.add_header('Content-ID', f'<{image}>')
                img.add_header('Content-Disposition', 'inline', filename=image)
            email.attach(img)
            
            email.send()
            return True

        except :
            return False

    @staticmethod
    def password_validation(password) -> bool:
        try:
            if len(password) < 8:
                return False
            if re.search("[a-z]", password) is None:
                return False
            if re.search("[A-Z]", password) is None:
                return False
            if re.search("[0-9]", password) is None:
                return False
            if re.search("[_@$]", password) is None:
                return False
            return True
        except:
            return False

    # @staticmethod
    # def authenticate_jwt(verification_jwt_token) -> dict:
    #     try:
    #         payload = jwt.decode(
    #             jwt=verification_jwt_token,
    #             key=SIMPLE_JWT["SIGNING_KEY"],
    #             algorithms=SIMPLE_JWT["ALGORITHM"],
    #         )
    #         return {
    #             "message": "Valid Mail verification token",
    #             "status": status.HTTP_200_OK,
    #             "payload": payload,
    #         }
    #     except:
    #         return {
    #             "message": "Invalid verification Link. Please request a new verification.",
    #             "status": status.HTTP_403_FORBIDDEN,
    #         }

    # @staticmethod
    # def get_jwt_via_user_for_verification(payload) -> str:
    #     try:
    #         current_time = timezone.now()
    #         expriy_time = current_time + SIMPLE_JWT["EMAIL_VERIFY_TIME_LIMIT"]
    #         payload["exp"] = expriy_time
    #         payload["iat"] = current_time
    #         token = jwt.encode(
    #             payload=payload, key=SIMPLE_JWT["SIGNING_KEY"], algorithm="HS256"
    #         )
    #         return token
    #     except Exception as e:
    #         raise Exception(
    #             "Unable to generate the auth link, pls try again later.")

    @staticmethod
    def validate_and_confirm_password(password, confirm_password) -> None:
        try:
            if not password or not confirm_password:
                raise ValueError("Password and Confirm Password are required")
            if password != confirm_password:
                raise ValueError("Password and Confirm Password do not match")
            if not Utils.password_validation(password):
                raise ValueError(
                    "Enter a strong password with minimum 8 characters, having atleast one uppercase, one lowercase, one digit and one special character"
                )
        except ValueError as e:
            raise ValueError(str(e))


    @staticmethod
    def validate_passwords_and_extract_username(request) -> str:
        """
        Retrieves a validated user based on the provided request.

        This function is used in Email verification & Set Password view, and Reset Password view to:
            1. Validate the password and confirm password.
            2. Validate the access token and extract the user.

        Args:
            request (Request): The request object.

        Returns:
            User: The validated user object, or None if validation fails.
        """
        try:
            jwt_token = request.data.get("token", None)
            if not jwt_token:
                raise Exception("Invalid Authentication Link")
            
            password = request.data.get("password", None)
            confirm_password = request.data.get("password2", None)
            Utils.validate_and_confirm_password(password, confirm_password)

            res = Utils.authenticate_jwt(jwt_token)
            if res['status'] != 200:
                raise Exception(res['message'])
            return res['payload']['username']
        except Exception as e:
            raise Exception(e)
    
    @staticmethod
    def get_content_type(file_extension: str) -> str:
        if file_extension in ['jpg', 'jpeg']:
            return 'image/jpeg'
        elif file_extension in ['png']:
            return 'image/png'
        elif file_extension in ['gif']:
            return 'image/gif'
        elif file_extension in ['bmp']:
            return 'image/bmp'
        elif file_extension in ['pdf']:
            return 'application/pdf'
        elif file_extension in ['docx', 'doc']:
            return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        elif file_extension in ['xlsx', 'xls']:
            return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        elif file_extension in ['txt']:
            # return 'text/plain'
            return 'text/html'
        elif file_extension in ['zip']:
            return 'application/zip'
        elif file_extension in ['csv']:
            return 'text/csv'
        else:
            return 'application/octet-stream'

    # @staticmethod
    # def get_weaviate_client() -> weaviate.Client:
    #     auth_config = weaviate.AuthApiKey(api_key=WEAVIATE_API_KEY)
    #     client = weaviate.connect_to_weaviate_cloud(
    #         cluster_url=WEAVIATE_URL_INSTANCE,
    #         auth_credentials=auth_config
    #     )
    #     return client

    @staticmethod
    def to_camel_case(file_name: str, user_id: int, service_name: str):
        try:
            name = f'{service_name}__{file_name}__{user_id}'
            name = ''.join(ch if ch.isalnum() else ' ' for ch in name)
            return ''.join(word.capitalize() for word in name.split())
        except:
            return None

    @staticmethod
    def format_size_unit(size_in_bytes):
        size_in_kb = round(size_in_bytes / 1024, 2)
        size_in_mb = round(size_in_kb / 1024, 2)
        size_in_gb = round(size_in_mb / 1024, 2)

        if size_in_gb >= 1:
            return size_in_gb, 'GB'
        elif size_in_mb >= 1:
            return size_in_mb, 'MB'
        else:
            return size_in_kb, 'KB'
        
    # @staticmethod
    # def encrypt_value(value):
    #     f = Fernet(FIELD_ENCRYPTION_KEY)
    #     encrypted_value = f.encrypt(value.encode())
    #     return encrypted_value.decode()
    
    # @staticmethod
    # def decrypt_value(encrypted_value):
    #     f = Fernet(FIELD_ENCRYPTION_KEY)
    #     decrypted_value = f.decrypt(encrypted_value.encode())
    #     return decrypted_value.decode()

    # @staticmethod
    # def get_blob_service_client():
    #     try:
    #         blob_service_client = BlobServiceClient(
    #             account_url=f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net",
    #             credential=STORAGE_ACCOUNT_ACCESS_KEY,
    #         )
    #         return blob_service_client
    #     except Exception as e:
    #         raise Exception(f"Unable to connect to Azure Blob Storage: {str(e)}")

    # @staticmethod
    # def get_container_client(blob_service_client):
    #     try:
    #         container_client = blob_service_client.get_container_client(CONTAINER_NAME)
    #         return container_client
    #     except Exception as e:
    #         raise Exception(f"Unable to get container: {str(e)}")

    # @staticmethod        
    # def download_blob_data(sas_url):
    #     try:
    #         blob_client = BlobClient.from_blob_url(sas_url)
    #         return blob_client.download_blob().readall()
    #     except:
    #         return None
    
    # @staticmethod
    # def create_sas_url(blob_service_client, blob_name):
    #     sas_token = generate_blob_sas(
    #         account_name=STORAGE_ACCOUNT_NAME,
    #         container_name=f'{CONTAINER_NAME}',
    #         blob_name=blob_name,
    #         account_key=blob_service_client.credential.account_key,
    #         permission=BlobSasPermissions(read=True),
    #         expiry=datetime.utcnow() + timedelta(days=READ_URL_EXP_DAYS)
    #     )

    #     blob_url = f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net/{CONTAINER_NAME}/{blob_name}?{sas_token}"
    #     return blob_url

    @staticmethod
    def format_size_unit(size_in_bytes):
        size_in_kb = round(size_in_bytes / 1024, 2)
        size_in_mb = round(size_in_kb / 1024, 2)
        size_in_gb = round(size_in_mb / 1024, 2)
        
        if size_in_gb >= 1:
            return size_in_gb, 'GB'
        elif size_in_mb >= 1:
            return size_in_mb, 'MB'
        else:
            return size_in_kb, 'KB'
        
