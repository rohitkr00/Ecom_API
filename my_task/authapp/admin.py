from django.contrib import admin
from .models import UserDetails, UserLogin, Products, AdminLogin, Transaction, Category, Subcategory

# Register your models here.
admin.site.register(UserDetails)
admin.site.register(UserLogin)
admin.site.register(Subcategory)
admin.site.register(Products)
admin.site.register(AdminLogin)
admin.site.register(Transaction)
admin.site.register(Category)