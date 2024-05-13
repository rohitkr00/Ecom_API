from django.shortcuts import render, redirect
from django.http import HttpResponse
from ..models import Products, UserDetails, UserLogin, Category, Cart
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
import razorpay
from django.conf import settings
from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist
import json
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from django.views import View



# =============================================================================================================
# =============================================================================================================
# =============================================================================================================
# =============================================================================================================


# =============================================================================================================
# =============================================================================================================
# =============================================================================================================
# =============================================================================================================



class HomeView(View):
    def get_querydata(self, *args, **kwargs):
        return Products.objects.filter(*args, **kwargs)

    def get(self, request):
        try:
            products = self.get_querydata()  # Retrieve all products from the database
            return render(request, 'ecomapp/home.html', {'products': products})
        except Exception as e:
            return HttpResponse("An error occurred: {}".format(str(e)))
    

class SignupView(View):
    def get(self, request):
        return render(request, 'ecomapp/components/signup.html')
    
    def post(self, request):
       
        try:
            user_data = {field: request.POST.get(field) for field in ['name', 'email', 'password', 'gender', 'adress', 'phone']}
            existing_user = User.objects.filter(email=user_data['email'])
            if existing_user:
                return render(request, 'ecomapp/home.html', {'message':"data is already exist"})
            else:
                user = User.objects.create_user(first_name=user_data['name'], username=user_data['email'], email=user_data['email'], password=user_data['password'])
                user.save()
                return render(request, 'ecomapp/home.html')
        except Exception as e:
            return HttpResponse("An error occurred: {}".format(str(e)))
        

class  HandleLoginView(View):
    
    
    def get(self, request):
        try:
            return render(request,'ecomapp/components/login.html')
        except Exception as e:
            return HttpResponse("An error occurred: {}".format(str(e)))
    
    def post(self, request):
        try:
            username=request.POST.get('email')
            userpassword=request.POST.get('password')

            user =User.objects.filter(username=username).first()

            if user is None:
                # messages.warning(request, 'user is not registered')
                return render(request,"ecomapp/home.html", {"message":"user is not registered"})

            
            myuser = authenticate(username=username, password=userpassword)


            if myuser is not None:
               
                login(request, myuser)
                request.session['user_id'] = myuser.id
                return render(request,"ecomapp/home.html", {"user": user})
            
            else:
                # messages.error(request,"Invalid Credentials")
                
                return render(request, "ecomapp/home.html")
        except Exception as e:
            return HttpResponse("An error occurred: {}".format(str(e)))
        
        # return render(request,"login.html")

class HandleLogoutView(View):
    def get(self, request):
        try:
            logout(request)
            return redirect('/Authapp/login')
        except Exception as e:
            return HttpResponse("An error occurred: {}".format(str(e)))

# =============================================================================================================
# =============================================================================================================
# =============================================================================================================
# =============================================================================================================



class ProductView(View):
    def get(self, request):
        try:
            categories = Category.objects.prefetch_related('products').all()

            return render(request, 'ecomapp/products.html', {'categories': categories})
        except Exception as e:
            return HttpResponse("An error occurred: {}".format(str(e)))
        
    def post(self, request):
        try:
            product_for_search = request.POST.get('name')
            search_product = Products.objects.filter(product_name__icontains = product_for_search)
            return render(request, 'ecomapp/components/search.html', {'products': search_product})
        except Exception as e:
            return HttpResponse("An error occurred: {}".format(str(e)))


# =============================================================================================================
# =============================================================================================================
# =============================================================================================================
# =============================================================================================================




class ProfileView(View):
    def get(self, request):
        try:
            if request.user.is_authenticated:  # Check if the user is authenticated
                user_req = request.user
                user_details = User.objects.filter(email=user_req.email).first()
                return render(request, "ecomapp/components/profile.html", {"user":user_details})
        except Exception as e:
            return HttpResponse("An error occurred: {}".format(str(e)))


# =============================================================================================================
# =============================================================================================================
# =============================================================================================================
# =============================================================================================================



class CartView(View):
    def post(self, request):
        try:
            if request.user.is_authenticated:
                product_id = request.POST.get('product_id')
                user_id = request.user.id
                
                try:
                    cart_object = Cart.objects.get(user_id_id=user_id, Product_id_id=product_id)
                    if cart_object:
                        cart_object.quantity +=1
                        cart_object.save()
                        return redirect("cart")
                except ObjectDoesNotExist:
                    cart = Cart(user_id_id=user_id, Product_id_id=product_id)
                    cart.save()
                    return redirect("cart")
            else:
                return render(request, "ecomapp/components/login.html", {"message":"You are not Authenticated"})
        except Exception as e:
            return HttpResponse("An error occurred: {}".format(str(e)))
        # return None
    def get(self, request):
        try:
            if request.user.is_authenticated:
                # Fetch cart items for the authenticated user
                cart_items = Cart.objects.select_related('Product_id__category').filter(user_id=request.user)

                products_with_quantities = []
                total_price = 0

                # Iterate over cart items and gather product details
                for cart_item in cart_items:
                    product = cart_item.Product_id
                    quantity = cart_item.quantity
                    amount = product.price * quantity

                    # Append product details to the list
                    products_with_quantities.append({
                        "id": product.id,
                        "product": product,
                        "quantity": quantity,
                        "amount": amount,
                        "category": product.category  # Include category details
                    })

                    # Accumulate total price
                    total_price += amount

                # Pass the required data to the template
                return render(
                    request,
                    "ecomapp/components/cart.html",
                    {
                        "products": products_with_quantities,
                        "total_price": total_price,
                    },
                )
            else:
                return render(request, "ecomapp/components/login.html", {"message": "You are not Authenticated"})
        except Exception as e:
            return HttpResponse("An error occurred: {}".format(str(e)))
       
    
        
        

class CartDeleteView(View):
    def post(self, request):
        try:
            p_id = request.POST.get('product_id')
            u_id = request.user.id
            product_delete = Cart.objects.filter(user_id = u_id,Product_id = p_id)
            product_delete.delete()
            # return render(request, "ecomapp/components/cart.html")
            return redirect('/Authapp/cart')
        except Exception as e:
            return HttpResponse("An error occurred: {}".format(str(e)))
        

# =============================================================================================================
# =============================================================================================================
# =============================================================================================================
# =============================================================================================================





class CreateOrderView(View):
    # @csrf_exempt
    def post(self, request):
        try:
            data = json.loads(request.body)  # Parse incoming JSON data
            # Get the payment amount from the frontend
            payment_amount = data["amount"]
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            # Create Razorpay order
            order = client.order.create({
                "amount": payment_amount,
                "currency": "INR",
                "payment_capture": "1"
            })
            # Return order details to frontend
            return JsonResponse({
                "order_id": order["id"],
                "razorpay_key": settings.RAZORPAY_KEY_ID,
                "amount": payment_amount,
            })
        except Exception as e:
            return HttpResponse("An error occurred: {}".format(str(e)))
    
