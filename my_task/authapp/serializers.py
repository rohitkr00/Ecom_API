from rest_framework import serializers
from .models import UserDetails, UserLogin, Products, AdminLogin, Transaction

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model=UserDetails
        fields="__all__"



class UserLoginSerializer(serializers.ModelSerializer):
    
    class Meta:
        model=UserLogin
        fields="__all__"



class AdminLoginSerializer(serializers.ModelSerializer):


    class Meta:
        model=AdminLogin
        fields="__all__"



class ProductSerializer(serializers.ModelSerializer):

    class Meta:
        model=Products
        fields="__all__"



class RazorpayOrderSerializer(serializers.Serializer):
    amount = serializers.IntegerField()
    currency = serializers.CharField()


class TranscationModelSerializer(serializers.ModelSerializer):

    class Meta:
        model = Transaction
        fields = ["payment_id", "order_id", "signature", "amount"]