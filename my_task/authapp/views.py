from django.shortcuts import render

# Create your views here.from django.shortcuts import render
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.contrib.auth import authenticate, login, logout
from django.contrib.sessions.models import Session
from django.contrib.auth.hashers import check_password
from .utils import generate_jwt, decode_token
from .main import RazorpayClient
import jwt
import smtplib
from .models import UserDetails, UserLogin, Products, AdminLogin, Transaction
from .serializers import UserSerializer, UserLoginSerializer, ProductSerializer, AdminLoginSerializer, TranscationModelSerializer, RazorpayOrderSerializer



@api_view(['POST', 'GET'])
def register_view(request):
    if request.method=='POST':
        data=request.data
        email1=data.get('email')
        password1=data.get('password')

        if UserLogin.objects.filter(email=email1).exists():
            return Response({
            "message":"email is already registered"
        }, status=status.HTTP_400_BAD_REQUEST)


        data2={'email':email1, 'password': password1}
        serializer=UserSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            data11=UserLogin.objects.create(
            email=email1,
            password=password1
        )
            data11.save()
            # print(serializer_login)
            # serializer_login.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({
            "message":"Data is not valid"
        }, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method=='GET':
        query_data=UserDetails.objects.all()
        if query_data.exists():
            task_data=UserSerializer(query_data, many=True)
            return Response(task_data.data, status=status.HTTP_200_OK)
        return Response({"message": "No User found"}, status=status.HTTP_404_NOT_FOUND)
    
    


@api_view(['POST'])
def admin_register_view(request):
    data = request.data
    email1 = data.get('email')

    if AdminLogin.objects.filter(email=email1).exists():
        return Response({
            "message":"email is already registered"
        }, status=status.HTTP_400_BAD_REQUEST)
    else:
        serializer = AdminLoginSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({
            "message":"Data is not valid"
        }, status=status.HTTP_400_BAD_REQUEST)




@api_view(['POST'])
def login_view(request):
    # how to store response in local storage in react
    data = request.data
    email = data.get("email")
    password = data.get("password")
    admin_login_data = AdminLogin.objects.filter(email=email, password=password)
    login_data = UserLogin.objects.filter(email=email, password=password)
    # user_data = UserLoginSerializer(user)
    # print(user_data.data)

    if admin_login_data:
        user = authenticate(request, username=email, password=password)
        if user is not None:
            login(request, user)
            # set user-specific data in the session
            request.session['username'] = email
            request.session.save()
            return Response({"message": "login success"}, status=status.HTTP_200_OK)
        else:
            response={
        "meggage": "Authentication failed for admin",
        }
        return Response(response, status=status.HTTP_400_BAD_REQUEST)



    elif login_data:
        token = generate_jwt(data)
        queryset=UserDetails.objects.get(email=data.get("email"))
        user_data=UserSerializer(queryset)
        response = {
        "meggage": "Logined success",
        "jwt": token,
        "u_data": user_data.data
        }
        # response.set_cookie(key="jwt", value=token)
        return Response(response, status=status.HTTP_200_OK)
    else:
        response={
        "meggage": "Invalid Username or Password",
        }
        return Response(response, status=status.HTTP_400_BAD_REQUEST)
    




@api_view(['POST','GET','PUT','PATCH','DELETE'])
def register_product(request):
        if request.method == 'POST':
            data = request.data
            serializer = ProductSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message" : "product inserted succesfully"}, status=status.HTTP_200_OK)
            else:
                response={
            "meggage": "Invalid data",
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
    
        elif request.method == 'GET':
            query_data=Products.objects.all()
            if query_data.exists():
                task_data=ProductSerializer(query_data, many=True)
                return Response(task_data.data, status=status.HTTP_200_OK)
            return Response({"message": "No User found"}, status=status.HTTP_404_NOT_FOUND)
        

        elif request.method == 'DELETE':
            query_data=Products.objects.get(id=request.data.get('id'))
            if query_data.exists():
                query_data.delete()
                return Response({'msg': 'Product deleted successfully'}, status=status.HTTP_200_OK)
            return Response({"message": "No product found"}, status=status.HTTP_404_NOT_FOUND)
        

        elif request.method == 'PATCH':
            query_data=Products.objects.get(id=request.data.get('id'))
            serializer = ProductSerializer(query_data, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({'msg': 'Product updated successfully'}, status=status.HTTP_200_OK)
            return Response({"message": "No product found"}, status=status.HTTP_404_NOT_FOUND)
    
        else:
            response={
            "meggage": "It can not processed",
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
        
    
@api_view(['POST'])
def product_search(request):
    if request.method == "POST":
        data = request.data.get('name')
        query_data = Products.objects.filter(product_name__icontains=data)
        if query_data.exists():
            task_data = ProductSerializer(query_data, many=True)
            return Response(task_data.data, status=status.HTTP_200_OK)
        return Response({"message": "No data found"}, status=status.HTTP_404_NOT_FOUND)
    

    
@api_view(['POST'])
def user_search(request):
    if request.method == "POST":
        data = request.data.get('name')
        query_data = Products.objects.filter(name__icontains=data)
        if query_data.exists():
            task_data = ProductSerializer(query_data, many=True)
            return Response(task_data.data, status=status.HTTP_200_OK)
        return Response({"message": "No data found"}, status=status.HTTP_404_NOT_FOUND)
    


    # =======================================Razorpay==================================================


rz_client = RazorpayClient()
@api_view(['POST'])
def order_initiate(request):
    razorpay_order_serializer = RazorpayOrderSerializer(
            data=request.data
        )
    if razorpay_order_serializer.is_valid():
            order_response = rz_client.create_order(
                amount=razorpay_order_serializer.validated_data.get("amount"),
                currency=razorpay_order_serializer.validated_data.get("currency")
            )
            response = {
                "status_code": status.HTTP_201_CREATED,
                "message": "order created",
                "data": order_response,
                
            }
            return Response(response, status=status.HTTP_201_CREATED)
    else:
            response = {
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": "bad request",
                "error": razorpay_order_serializer.errors
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def transaction_view(request):
    transaction_serializer = TranscationModelSerializer(data=request.data)
    if transaction_serializer.is_valid():
            rz_client.verify_payment_signature(
                razorpay_payment_id = transaction_serializer.validated_data.get("payment_id"),
                razorpay_order_id = transaction_serializer.validated_data.get("order_id"),
                razorpay_signature = transaction_serializer.validated_data.get("signature")
            )
            transaction_serializer.save()
            response = {
                "status_code": status.HTTP_201_CREATED,
                "message": "transaction created"
            }
            return Response(response, status=status.HTTP_201_CREATED)
    else:
            response = {
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": "bad request",
                "error": transaction_serializer.errors
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)