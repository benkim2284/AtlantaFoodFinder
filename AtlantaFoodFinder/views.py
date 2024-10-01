from django.http import JsonResponse, HttpResponse

from django.contrib.auth import authenticate, login, logout
from .forms import RegisterForm
from django.views.decorators.csrf import csrf_exempt
import json

from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator, MaxLengthValidator

from django.contrib.auth.models import User

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import Restaurant, Review, Favorite
from .forms import ReviewForm
from django.contrib import messages
import hashlib

class RegisterForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput,
        validators=[
            MinLengthValidator(8),
            MaxLengthValidator(30)
        ]
    )
    confirm_password = forms.CharField(widget=forms.PasswordInput)
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    # Validate username
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if username.strip() == '':
            raise ValidationError("Username cannot be blank or whitespace.")
        if len(username) < 4 or len(username) > 30:
            raise ValidationError("Username must be between 4 and 30 characters.")
        if User.objects.filter(username=username).exists():
            raise ValidationError("Username already exists.")
        return username

    # Validate password
    def clean_password(self):
        password = self.cleaned_data.get('password')
        if password.strip() == '':
            raise ValidationError("Password cannot be blank or whitespace.")
        return password

    # Validate email
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not email:
            raise ValidationError("Email is required.")
        if User.objects.filter(email=email).exists():
            raise ValidationError("An account with this email already exists.")
        return email

    # Ensure passwords match
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        if password and confirm_password and password != confirm_password:
            raise ValidationError("Passwords do not match.")

def map_view(request):
    return render(request, 'AtlantaFoodFinder/index.html')


def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])  # Hash the password
            user.save()
            login(request, user)
            return redirect('AtlantaFoodFinder:login')
    else:
        form = RegisterForm()
    return render(request, 'AtlantaFoodFinder/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('AtlantaFoodFinder:map')
        else:
            return render(request, 'AtlantaFoodFinder/login.html', {'error': 'Invalid credentials'})
    else:
        return render(request, 'AtlantaFoodFinder/login.html')

@login_required
@csrf_exempt
def logout_view(request):
    if request.method == 'POST':
        logout(request)
        return HttpResponse(status=200)
    else:
        return HttpResponse(status=500)

def home_view(request):
    # Check if the user is authenticated
    return render(request, 'AtlantaFoodFinder/home.html')

@login_required
@csrf_exempt
def add_favorite_place(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            place_id = data.get('place_id')
            name = data.get('name')
            location = data.get('location')
            formatted_address = data.get('formatted_address')

            existing_favorite = Favorite.objects.filter(
                user=request.user,
                place_id=place_id  # You can also check using 'location' if needed
            ).exists()

            if existing_favorite:
                return JsonResponse({'error': 'This location is already favorited.'}, status=400)

            # Create a new FavoritePlace and save it to the database
            favorite = Favorite(user=request.user, place_id=place_id, name=name, location = location, formatted_address = formatted_address)
            favorite.save()

            return JsonResponse({'message': 'Favorite place added successfully'}, status=201)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@login_required
@csrf_exempt
def get_favorites(request):
    if request.method == 'GET':
        try:
            existing_favorites = Favorite.objects.filter(
                user=request.user,
            ).values('place_id', 'name', 'location', 'formatted_address')
            return JsonResponse({'existing_favorites': list(existing_favorites)}, status=201)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@login_required
@csrf_exempt
def remove_favorite(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            place_id = data.get('place_id')

            # Check if the favorite place exists for the logged-in user
            favorite = Favorite.objects.filter(user=request.user, place_id=place_id).first()

            if favorite:
                favorite.delete()  # Remove the favorite place
                return JsonResponse({'message': 'Favorite place removed successfully'}, status=200)
            else:
                return JsonResponse({'error': 'Favorite place not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Invalid request method'}, status=405)



def password_reset_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        old_password = request.POST.get('old_password')
        new_password1 = request.POST.get('new_password1')
        new_password2 = request.POST.get('new_password2')

        if not username or not old_password or not new_password1 or not new_password2:
            messages.error(request, "Please fill out all fields.")
            return render(request, 'AtlantaFoodFinder/password_reset.html')

        user = authenticate(request, username=username, password=old_password)

        if user is not None:
            if new_password1 != new_password2:
                messages.error(request, "New passwords do not match.")
                return render(request, 'AtlantaFoodFinder/password_reset.html')

            # Optional password validation (length between 8 and 30 characters)
            if len(new_password1) < 8 or len(new_password1) > 30:
                messages.error(request, "New password must be between 8 and 30 characters.")
                return render(request, 'AtlantaFoodFinder/password_reset.html')

            user.set_password(new_password1)
            user.save()
            messages.success(request, "Your password has been reset successfully.")
            return redirect('AtlantaFoodFinder:login')
        else:
            messages.error(request, "Invalid username or old password.")
            return render(request, 'AtlantaFoodFinder/password_reset.html')
    else:
        return render(request, 'AtlantaFoodFinder/password_reset.html')
@login_required
@csrf_exempt
def check_add_restaurant(request):
    if request.method == 'POST':
        data = json.loads(request.body)

        name = data.get('name')
        cuisine = data.get('cuisine')
        address = data.get('address')

        restaurant_hash = hash_address(address)

        exists = Restaurant.objects.filter(hashed_address=restaurant_hash).exists()
        try:
            if not exists:
                new_restaurant = Restaurant(hashed_address=restaurant_hash, name=name, cuisine=cuisine)
                new_restaurant.save()
                print("new restaurant")
                return JsonResponse({'message': restaurant_hash}, status=200)
            print("restaurant already exists")
            return JsonResponse({'message': restaurant_hash}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

def restaurant_detail(request, restaurant_hash):
    restaurant = Restaurant.objects.filter(hashed_address=restaurant_hash).first()

    if restaurant:
        reviews = restaurant.reviews.all()
    else:
        restaurant = None  # Set to None if restaurant doesn't exist
        reviews = []

    return render(request, 'AtlantaFoodFinder/restaurant_detail.html', {
        'restaurant': restaurant,
        'reviews': reviews
    })

@login_required
def add_review(request, restaurant_hash):
    restaurant = get_object_or_404(Restaurant, hashed_address=restaurant_hash)
    if request.method == 'POST':
        form = ReviewForm(request.POST)
        if form.is_valid():
            new_review = form.save(commit=False)
            new_review.restaurant = restaurant
            new_review.user = request.user
            new_review.save()
            messages.success(request, "Your review has been submitted.")

            restaurant = get_object_or_404(Restaurant, hashed_address=restaurant_hash)
            return redirect('AtlantaFoodFinder:restaurant_detail', restaurant_hash=restaurant.hashed_address)
    else:
        form = ReviewForm()
    return render(request, 'AtlantaFoodFinder/add_review.html', {
        'form': form,
        'restaurant': restaurant
    })

def user_reviews(request, username):
    user = get_object_or_404(User, username=username)
    reviews = Review.objects.filter(user=user).select_related('restaurant')
    return render(request, 'AtlantaFoodFinder/user_reviews.html', {
        'reviews': reviews,
        'review_user': user
    })


def hash_address(address) :
    address_bytes = address.encode('utf-8')
    hash_object = hashlib.sha256()
    hash_object.update(address_bytes)
    hashed_address = hash_object.hexdigest()
    return hashed_address
