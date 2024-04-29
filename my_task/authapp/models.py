from django.db import models

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



class Products(models.Model):
    product_name=models.CharField(max_length=100)
    category=models.CharField(max_length=100,default="")
    price=models.IntegerField(default="0")
    desc=models.CharField(max_length=300)

    def __str__(self):
        return self.product_name
    


class Transaction(models.Model):
    payment_id = models.CharField(max_length=200, verbose_name="Payment ID")
    order_id = models.CharField(max_length=200, verbose_name="Order ID")
    signature = models.CharField(max_length=500, verbose_name="Signature", blank=True, null=True)
    amount = models.IntegerField(verbose_name="Amount")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.id)