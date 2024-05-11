from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class UserDetails(models.Model):
    name=models.CharField(max_length=50)
    email=models.EmailField()
    password=models.CharField(max_length=200)
    gender=models.CharField(max_length=50)
    adress=models.CharField(max_length=300)
    phone=models.CharField(max_length=10)

        

    def __str__(self):
        return self.name

class UserLogin(models.Model):
    email=models.EmailField(max_length=254)
    password=models.CharField(max_length=254)


class AdminLogin(models.Model):
    email=models.EmailField(max_length=254)
    password=models.CharField(max_length=254)


class Category(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name
    

class Products(models.Model):
    product_name=models.CharField(max_length=100)
    category=models.ForeignKey(Category, on_delete=models.CASCADE )
    sub_category=models.CharField(max_length=100,default="")
    price=models.IntegerField(default="0")
    desc=models.CharField(max_length=300)
    product_image = models.ImageField(upload_to='product_images', default="null")

    def __str__(self):
        return self.product_name
    


class Subcategory(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    category = models.ForeignKey(Category, related_name='subcategories', on_delete=models.CASCADE)

    def __str__(self):
        return self.name


class Transaction(models.Model):
    payment_id = models.CharField(max_length=200, verbose_name="Payment ID")
    order_id = models.CharField(max_length=200, verbose_name="Order ID")
    signature = models.CharField(max_length=500, verbose_name="Signature", blank=True, null=True)
    amount = models.IntegerField(verbose_name="Amount")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.id)
    


class Cart(models.Model):
    user_id = models.CharField(max_length=200)
    Product_id = models.IntegerField(max_length=200)
    quantity = models.IntegerField(max_length=200, default=1)
