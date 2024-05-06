from django.urls import path
# from rest_framework import routers
from .views import web, api
# from views.api import(
# UserViewset, 
# LoginViewset, 
# AdminRegister,
# RegisterProduct, 
# ProductSearch, 
# UserSearch, 
# OrderInitiate, 
# TransactionView,
# CatagoryViewset,
# SubCatagoryViewset,

# )

urlpatterns = [
    path('register_view/', api.UserViewset.as_view()),
    path('login_view/', api.LoginViewset.as_view()),
    path('admin_register/', api.AdminRegister.as_view()),
    path('register_product/', api.RegisterProduct.as_view()),
    path('product_search/', api.ProductSearch.as_view()),
    path('user_search/', api.UserSearch.as_view()),
    path('order_create/', api.OrderInitiate.as_view()),
    path('order_complete/', api.TransactionView.as_view()),
    path('category_view/', api.CatagoryViewset.as_view()),
    path('sub_category_view/', api.SubCatagoryViewset.as_view()),

# ==================================================================

    path('', web.home, name='home'),
    path('signup/', web.Signup, name='signup'),
    path('login/', web.handlelogin, name='login'),
    path('logout/', web.handlelogout, name='logout'),
    path('product/', web.product, name='product'),
    path('profile/', web.profile, name='profile'),
    path('cart/', web.cart, name='cart'),
    path('cart_delete/', web.cart_delete, name='cart_delete'),
    

    # Add other URLs as needed
    ]