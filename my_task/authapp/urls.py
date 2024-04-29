from django.urls import path
from rest_framework import routers
from .views import register_view, login_view, admin_register_view, register_product, product_search, user_search, order_initiate, transaction_view


urlpatterns = [
    path('register_view/', register_view),
    path('login_view/', login_view),
    path('admin_register/', admin_register_view),
    path('register_product/', register_product),
    path('product_search/', product_search),
    path('user_search/', user_search),
    path('order_create/', order_initiate),
    path('order_complete/', transaction_view),

    # Add other URLs as needed
    ]