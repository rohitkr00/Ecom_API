from django.urls import path, include
from .views import web, api
from rest_framework.routers import DefaultRouter
from .firebase import send_notification , showFirebaseJS
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

router = DefaultRouter()
router.register(r'person_view', api.PersonViewSet, basename='person-view')


urlpatterns = [
    path('my_view/', api.my_view),
    path('register_view/', api.UserViewset.as_view()),
    path('login_view/', api.LoginViewset.as_view()),
    # path('admin_register/', api.AdminRegister.as_view()),
    path('register_product/', api.RegisterProduct.as_view()),
    path('product_search/', api.ProductSearch.as_view()),
    path('user_search/', api.UserSearch.as_view()),
    path('order_create/', api.OrderInitiate.as_view()),
    path('order_complete/', api.TransactionView.as_view()),
    path('category_view/', api.CatagoryViewset.as_view()),
    path('sub_category_view/', api.SubCatagoryViewset.as_view()),
    path('view/', include(router.urls)),

# ==================================================================

    path('', web.HomeView.as_view(), name='home'),
    path('signup/', web.SignupView.as_view(), name='signup'),
    path('login/', web.HandleLoginView.as_view(), name='login'),
    path('logout/', web.HandleLogoutView.as_view(), name='logout'),
    path('product/', web.ProductView.as_view(), name='product'),
    path('profile/', web.ProfileView.as_view(), name='profile'),
    path('cart/', web.CartView.as_view(), name='cart'),
    path('cart_delete/', web.CartDeleteView.as_view(), name='cart_delete'),
    path('create_order/', web.CreateOrderView.as_view(), name='create_order'),
    path('send_notification/', send_notification, name='send_notification'),
    
    

    # Add other URLs as needed
    ]