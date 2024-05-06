from django.shortcuts import render, redirect
from ..models import Products, UserDetails, UserLogin, Category, Cart
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User


def home(request):
    products = Products.objects.all()  # Retrieve all products from the database
    return render(request, 'ecomapp/home.html', {'products': products})

def Signup(request):
    if request.method == 'GET':
        return render(request, 'ecomapp/components/signup.html')
    
    elif request.method == 'POST':
        name=request.POST.get('name')
        username=request.POST.get('email')
        password=request.POST.get('password')
        gender=request.POST.get('gender')
        adress=request.POST.get('adress')
        phone=request.POST.get('phone')
        existing_user = User.objects.filter(email=username)
        if existing_user:
            return render(request, 'ecomapp/home.html', {'message':"data is already exist"})
        else:
            user = User.objects.create_user(first_name=name, username=username, email=username, password=password,)
            # user_login = UserLogin(email = email, password = password)
            user.save()
            # user_login.save()
            return render(request, 'ecomapp/home.html')
        

def handlelogin(request):
    if request.method=="GET":
        return render(request,'ecomapp/components/login.html')
    elif request.method=="POST":
        username=request.POST.get('email')
        userpassword=request.POST.get('password')

        if User.objects.filter(email=username).exists() is False:
            print("user not exists")
            return render(request,"ecomapp/home.html", {"message":"user is not registered"})

        print(userpassword)
        myuser = authenticate(username=username, password=userpassword)
        print(myuser)

        if myuser is not None:
            
            user = User.objects.filter(username=username)
            # messages.success(request,"Login Success")
            print("logined")
            login(request, myuser)
            return render(request,"ecomapp/home.html", {"user": user})
        
        else:
            # messages.error(request,"Invalid Credentials")
            print("Not logind")
            return render(request, "ecomapp/home.html")
        
        # return render(request,"login.html")

def handlelogout(request):
    logout(request)
    return redirect('/Authapp/login')

def product(request):
    if request.method == "GET":    
        products = Products.objects.all()  # Retrieve all products from the database
        return render(request, 'ecomapp/products.html', {'products': products})
    elif request.method == "POST":
        product_for_search = request.POST.get('name')
        search_product = Products.objects.filter(product_name__icontains = product_for_search)
        return render(request, 'ecomapp/products.html', {'products': search_product})

def profile(request):
    if request.user.is_authenticated:  # Check if the user is authenticated
        user_req = request.user
        user_details = User.objects.filter(email=user_req.email).first()
        return render(request, "ecomapp/components/profile.html", {"user":user_details})


def cart(request):
    if request.method == 'POST' and request.user.is_authenticated:
        product_id = request.POST.get('product_id')
        print(product_id)
        user_query = request.user
        user_id = user_query.email
        # user = User.objects.filter(email=user_id)
        
        cart = Cart(user_id=user_id, Product_id=product_id)
        cart.save()
        return redirect("cart")
        # return None
    elif request.method == 'GET'and request.user.is_authenticated:
        user_mail=request.user.email
        cart_item = Cart.objects.filter(user_id=user_mail)
      
        product_ids_incart = cart_item.values_list('Product_id', flat=True)
        products_in_cart = Products.objects.filter(id__in=product_ids_incart)
        print(products_in_cart)
        total_price=0
        for product in products_in_cart:
            total_price += product.price
        return render(request, "ecomapp/components/cart.html", { "products":products_in_cart, "total_price": total_price, "cart_items":cart_item})
    

    else:
        return render(request, "ecomapp/components/login.html", {"message":"You are not Authenticated"})
        

def cart_delete(request):
    if request.method == 'POST':
        p_id = request.POST.get('product_id')
        product_delete = Cart.objects.filter(Product_id = p_id)
        product_delete.delete()
        # return render(request, "ecomapp/components/cart.html")
        return redirect('/Authapp/cart')