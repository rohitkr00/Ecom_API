import jwt
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta

from my_task import settings


def generate_jwt(payload):
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256'

                      )

# def generate_jwt(user):
#     refresh = RefreshToken.for_user(user)
    
#     # Set the expiration time for the access token
#     access_token = str(refresh.access_token)
    
#     # Include the 'exp' claim in the payload
#     access_token_payload = refresh.access_token.payload
#     access_token_payload['exp'] = int((refresh.access_token.current_time + timedelta(minutes=60)).timestamp())
    
#     return access_token


def decode_token(token):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        return payload
    except jwt.ExpiredSignatureError:
        return Response({
            "message": "Invalid Signature"
        })
    except jwt.InvalidTokenError:
        return Response({
            "message": "Invalid Token"
        })


