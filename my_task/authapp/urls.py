from django.urls import path
from rest_framework import routers
from .views import UserViewset, LoginViewset, AdminRegister, RegisterProduct, ProductSearch, UserSearch, OrderInitiate, TransactionView


urlpatterns = [
    path('register_view/', UserViewset.as_view()),
    path('login_view/', LoginViewset.as_view()),
    path('admin_register/', AdminRegister.as_view()),
    path('register_product/', RegisterProduct.as_view()),
    path('product_search/', ProductSearch.as_view()),
    path('user_search/', UserSearch.as_view()),
    path('order_create/', OrderInitiate.as_view()),
    path('order_complete/', TransactionView.as_view()),

    # Add other URLs as needed
    ]