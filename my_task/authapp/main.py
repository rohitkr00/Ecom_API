from .import client
from rest_framework.serializers import ValidationError
from rest_framework import status

# from django.contrib.auth.backends import BaseBackend
# from django.contrib.auth.hashers import check_password  # For password verification
# from .models import UserDetails  # Your custom user model


class RazorpayClient:

    def create_order(self, amount, currency):
        data = {
            "amount": amount * 100,
            "currency": currency,
        }
        try:
            self.order = client.order.create(data=data)
            return self.order
        except Exception as e:
            raise ValidationError(
                {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": e
                }
            )
    
    def verify_payment_signature(self, razorpay_order_id, razorpay_payment_id, razorpay_signature):
        try:
            self.verify_signature = client.utility.verify_payment_signature({
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            })
            return self.verify_signature
        except Exception as e:
            raise ValidationError(
                {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "message": e
                }
            )
            




# class CustomAuthBackend(BaseBackend):
#     def authenticate(self, request, username=None, password=None, **kwargs):
#         try:
#             # Try to find a user by username (or email, depending on your needs)
#             user = UserDetails.objects.get(email=username)
#             # Check if the password matches
#             if check_password(password, user.password):
#                 return user
#         except UserDetails.DoesNotExist:
#             return None

#     def get_user(self, user_id):
#         try:
#             return UserDetails.objects.get(pk=user_id)
#         except UserDetails.DoesNotExist:
#             return None



