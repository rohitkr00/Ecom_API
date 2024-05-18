from django.shortcuts import render
from django.contrib.auth.models import User
from rest_framework import viewsets
import logging
from django.core.serializers import deserialize
from django.contrib.auth.hashers import make_password
from authapp.tasks import send_notification
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import check_password
from django.contrib.sessions.models import Session
from django.contrib.auth.hashers import check_password
from ..utils import generate_jwt, decode_token
from ..main import RazorpayClient
from rest_framework.pagination import PageNumberPagination
import jwt
import smtplib
from ..models import UserDetails, UserLogin, Products, AdminLogin, Transaction, Category, Subcategory
from ..serializers import (
UserSerializer, 
UserLoginSerializer, 
ProductSerializer, 
AdminLoginSerializer, 
TranscationModelSerializer, 
RazorpayOrderSerializer,
CatagorySerializer,
SubCatagorySerializer,
UserDefaultSerializer,
)
from django.views import generic

logger = logging.getLogger(__name__)
# ==============================================================================================

class UserViewset(APIView):

    def get_serializer(self, *args, **kwargs):
        return UserDefaultSerializer(*args, **kwargs)
    
    def get_querydata(self, *args, **kwargs):
        return User.objects.filter(*args, **kwargs)
     
    def get(self, request):
        try:
            query_data=self.get_querydata()
            if query_data.exists():
                serializer=self.get_serializer(query_data, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response({"message": "No User found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as ex:
            logger.error("Error fetching users", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def post(self, request):
        try:
            data=request.data
            email1=data.get('email')
            password1=data.get('password')
            # hashed_password = make_password(password1)
            # data['password'] = hashed_password
            # print(data)
            if self.get_querydata(email=email1).exists():
                return Response({
                "message":"email is already registered"
            }, status=status.HTTP_400_BAD_REQUEST)
            serializer=self.get_serializer(data=data)
            

            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response({
                "message":"Data is not valid"
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as ex:
            logger.error("Error fetching users", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


    def patch(self, request):
            try:
                data = request.data
                user_id = data.get('id')
                print(user_id)
                user=self.get_querydata(id=user_id).first()
                # current_user = user.first()
                print(user)
                serializer = self.get_serializer(user, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response({'msg': 'User updated successfully'}, status=status.HTTP_200_OK)
                return Response({"message": "No User found"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as ex:
                logger.error("Error fetching users", exc_info=True)
                return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def delete(self, request):
        try:
            user=self.get_querydata(id=request.data.get('id'))
            # query_data_login=UserLogin.objects.filter(id=request.data.get('id'))
            if user.exists():
                user.delete()
                # query_data_login.delete()
                return Response({'msg': 'User deleted successfully'}, status=status.HTTP_200_OK)
            return Response({"message": "No user found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as ex:
            logger.error("Error fetching users", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
# =========================================================================================================
# =========================================================================================================
# =========================================================================================================

# class AdminRegister(APIView):
#     def post(self, request):
#         data = request.data
#         email1 = data.get('email')

#         if AdminLogin.objects.filter(email=email1).exists():
#             return Response({
#                 "message":"email is already registered"
#             }, status=status.HTTP_400_BAD_REQUEST)
#         else:
#             serializer = AdminLoginSerializer(data=data)
#             if serializer.is_valid():
#                 serializer.save()
#                 return Response(serializer.data, status=status.HTTP_200_OK)
#             return Response({
#                 "message":"Data is not valid"
#             }, status=status.HTTP_400_BAD_REQUEST)




class LoginViewset(APIView):
    def get_querydata(self, *args, **kwargs):
         return User.objects.filter(*args, **kwargs)

    def post(self, request):
        data = request.data
        email = data.get("email")
        password = data.get("password")
        # admin_login_data = AdminLogin.objects.filter(email=email, password=password)
        try:
            user = self.get_querydata(email=email).first()
            if check_password(password, user.password):
                login(request, user)
            # set user-specific data in the session
                request.session['username'] = email
                request.session['is_logged_in'] = True
                request.session.save()
                return Response({"message": "login success"}, status=status.HTTP_200_OK)
            else:
                response={
            "message": "Authentication failed for admin",
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except Exception as ex:
            logger.error("Error in login", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        # user_data = UserLoginSerializer(user)
        # print(user_data.data)

        


# this is for token authentication 
        # elif login_data:
        #     token = generate_jwt(data)
        #     queryset=UserDetails.objects.get(email=data.get("email"))
        #     user_data=UserSerializer(queryset)
        #     response = {
        #     "meggage": "Logined success",
        #     "jwt": token,
        #     "u_data": user_data.data
        #     }
        #     # response.set_cookie(key="jwt", value=token)
        #     return Response(response, status=status.HTTP_200_OK)
        # else:
        #     response={
        #     "meggage": "Invalid Username or Password",
        #     }
        #     return Response(response, status=status.HTTP_400_BAD_REQUEST)
        

# ==========================================================================================================
# ==========================================================================================================
# ==========================================================================================================


class RegisterProduct(APIView):

    def get_serializer(self, *args, **kwargs):
        return ProductSerializer(*args, **kwargs)
    
    def get_querydata(self, *args, **kwargs):
        return Products.objects.filter(*args, **kwargs)
    
    def post(self, request):
        data = request.data
        try:
            serializer = self.get_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message" : "product inserted succesfully"}, status=status.HTTP_200_OK)
            else:
                response={
            "meggage": "Invalid data",
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except Exception as ex:
            logger.error("Error in registration", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def get(self, request):
        try:
            query_data=Products.objects.select_related('category')
            if query_data.exists():
                paginator = PageNumberPagination()
                paginator.page_size = 2
                paginationdata = paginator.paginate_queryset(query_data, request)
                serializer=self.get_serializer(paginationdata, many=True)
                return paginator.get_paginated_response(serializer.data)
            return Response({"message": "No Product found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as ex:
            logger.error("Error fetching Products", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

    def delete(self, request):
        try:
            query_data=self.get_querydata(id=request.data.get('id')).first()
            if query_data.exists():
                query_data.delete()
                return Response({'msg': 'Product deleted successfully'}, status=status.HTTP_200_OK)
            return Response({"message": "No product found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as ex:
            logger.error("Error fetching Products", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

    def patch(self, request):
        try:
            query_data=self.get_querydata(id=request.data.get('id')).first()
            serializer = self.get_serializer(query_data, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({'msg': 'Product updated successfully'}, status=status.HTTP_200_OK)
            return Response({"message": "No product found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as ex:
            logger.error("Error fetching Products", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# ==================================================================================================================
# ============================================Searching=============================================================
# ==================================================================================================================
    
class ProductSearch(APIView):
    def get_serializer(self, *args, **kwargs):
        return ProductSerializer(*args, **kwargs)
    
    def get_querydata(self, *args, **kwargs):
        return Products.objects.filter(*args, **kwargs)
    
    def post(self, request):
        try:
            if request.data is None:
                return Response({"message": "Please Enter data which you want to find"}, status=status.HTTP_404_NOT_FOUND)
            if request.method == "POST":
                data = request.data.get('name')
                query_data = self.get_querydata(product_name__icontains=data)
                if query_data.exists():
                    serializer = self.get_serializer(query_data, many=True)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({"message": "No data found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as ex:
            logger.error("Error fetching Products", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

    
class UserSearch(APIView):
    def get_serializer(self, *args, **kwargs):
        return UserDefaultSerializer(*args, **kwargs)
    
    def get_querydata(self, *args, **kwargs):
        return User.objects.filter(*args, **kwargs)
    
    def post(self, request):
        try:
            if request.method == "POST":
                data = request.data.get('name')
                query_data = self.get_querydata(name__icontains=data)
                if query_data.exists():
                    serializer = self.get_serializer(query_data, many=True)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({"message": "No data found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as ex:
            logger.error("Error fetching Products", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

#===================================================Razorpay=======================================================
#===================================================Razorpay=======================================================
#===================================================Razorpay=======================================================


class OrderInitiate(APIView):
    def get_serializer(self, *args, **kwargs):
        return RazorpayOrderSerializer(*args, **kwargs)
    
    def post(self, request):
        try:
            razorpay_order_serializer = self.get_serializer(
                    data=request.data
                )
            if razorpay_order_serializer.is_valid():
                    rz_client = RazorpayClient()
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
        except Exception as ex:
            logger.error("Error in creating order", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TransactionView(APIView):
    def get_serializer(self, *args, **kwargs):
        return TranscationModelSerializer(*args, **kwargs)
    
    def post(self, request):
        try:
            transaction_serializer = self.get_serializer(data=request.data)
            if transaction_serializer.is_valid():
                    rz_client = RazorpayClient()
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
        except Exception as ex:
            logger.error("Error fetching users", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)






#===================================================Catagory=======================================================
#===================================================Catagory=======================================================
#===================================================Catagory=======================================================



class CatagoryViewset(APIView):
    def get_serializer(self, *args, **kwargs):
        return CatagorySerializer(*args, **kwargs)
    
    def get_querydata(self, *args, **kwargs):
        return Category.objects.filter(*args, **kwargs)
     
    def get(self, request):
        try:
            query_data=self.get_querydata()
            if query_data.exists():
                serializer=self.get_serializer(query_data, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response({"message": "No Category found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as ex:
            logger.error("Error fetching it", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
     
    def post(self, request):
        data=request.data
        try:
            name=data.get('name')

            if self.get_querydata(name=name).exists():
                return Response({
                "message":"Category is already registered"
            }, status=status.HTTP_400_BAD_REQUEST)


            
            serializer=self.get_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response({
                "message":"Data is not valid"
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as ex:
            logger.error("Error fetching it", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    


    def patch(self, request):
            try:
                query_data=self.get_querydata(id=request.data.get('id'))
                serializer = self.get_serializer(query_data, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response({'msg': 'category updated successfully'}, status=status.HTTP_200_OK)
                return Response({"message": "No Category found"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as ex:
                logger.error("Error fetching users", exc_info=True)
                return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def delete(self, request):
        try:
            query_data=self.get_querydata(id=request.data.get('id'))
            if query_data.exists():
                query_data.delete()
                return Response({'msg': 'Category deleted successfully'}, status=status.HTTP_200_OK)
            return Response({"message": "No Category found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as ex:
            logger.error("Error in delete category", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




#===================================================SubCatagory=======================================================
#===================================================SubCatagory=======================================================
#===================================================SubCatagory=======================================================





class SubCatagoryViewset(APIView):
    def get_serializer(self, *args, **kwargs):
        return SubCatagorySerializer(*args, **kwargs)
    
    def get_querydata(self, *args, **kwargs):
        return Subcategory.objects.filter(*args, **kwargs)
     
    def get(self, request):
        try:
            query_data=self.get_querydata()
            if query_data.exists():
                task_data=self.get_serializer(query_data, many=True)
                return Response(task_data.data, status=status.HTTP_200_OK)
            return Response({"message": "No Suncategory found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as ex:
            logger.error("Error fetching Category", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
     
    def post(self, request):
        data=request.data
        try:
            serializer=self.get_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response({
                "message":"Data is not valid"
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as ex:
            logger.error("Error fetching users", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    


    def patch(self, request):
        try:
            query_data=self.get_querydata(id=request.data.get('id'))
            serializer = self.get_serializer(query_data, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({'msg': 'Subcategory updated successfully'}, status=status.HTTP_200_OK)
            return Response({"message": "No Subcategory found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as ex:
            logger.error("Error fetching users", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def delete(self, request):
        try:
            query_data=self.get_querydata(id=request.data.get('id'))
            if query_data.exists():
                query_data.delete()
                return Response({'msg': 'Subcategory deleted successfully'}, status=status.HTTP_200_OK)
            return Response({"message": "No Subcategory found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as ex:
            logger.error("Error fetching users", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




# =======================================================================================================================
# =======================================================ViewSetClass====================================================
# =======================================================================================================================




class PersonViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserDefaultSerializer

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                send_notification.delay()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as ex:
            logger.error("Error fetching users", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as ex:
            logger.error("Error fetching users", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def partial_update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status= status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as ex:
            logger.error("Error fetching users", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            instance.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as ex:
            logger.error("Error fetching users", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        





@api_view(['GET'])
def my_view(request):
    # Call the Celery task
    result = send_notification()
    if result:
        return Response({"message": "successfull"}, status=status.HTTP_200_OK)
    else:
        return Response({"message":"False"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)