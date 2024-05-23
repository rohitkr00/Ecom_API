from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .models import UserDetails, UserLogin, Products, AdminLogin, Transaction, Category, Subcategory
from django.contrib.auth.models import User


class UserDefaultSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)  # Ensure password is write-only

    def create(self, validated_data):
        # Hash the password before saving
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)

    class Meta:
        model=User
        fields=['first_name','email','username','password']


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



class CatagorySerializer(serializers.ModelSerializer):

      class Meta:
        model=Category
        fields="__all__"


class ProductSerializer(serializers.ModelSerializer):
    category = CatagorySerializer()

    class Meta:
        model=Products
        fields="__all__"


class SubCatagorySerializer(serializers.ModelSerializer):

      class Meta:
        model=Subcategory
        fields="__all__"


class RazorpayOrderSerializer(serializers.Serializer):
    amount = serializers.IntegerField()
    currency = serializers.CharField()


class TranscationModelSerializer(serializers.ModelSerializer):

    class Meta:
        model = Transaction
        fields = ["payment_id", "order_id", "signature", "amount"]