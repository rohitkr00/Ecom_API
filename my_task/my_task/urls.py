
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt import views as jwt_views
from django.views.generic import RedirectView

if settings.DEBUG:
    import debug_toolbar

urlpatterns = [
    path('api/token/', jwt_views.TokenObtainPairView.as_view(), name ='token_obtain_pair'), 
    path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(), name ='token_refresh'), 
    path('debug/', include(debug_toolbar.urls)),
    path('admin/', admin.site.urls),
    path('logout/',RedirectView.as_view(url = '/admin/logout/')),
    path('Authapp/', include('authapp.urls')),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)



# cron
