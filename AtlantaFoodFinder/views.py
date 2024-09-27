from django.db.models import F
from django.http import JsonResponse

from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views import generic

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import RegisterForm
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from .models import Favorite
import json



def map_view(request):
    return render(request, 'AtlantaFoodFinder/index.html')


def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])  # Hash the password
            user.save()
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


def wassup_view(request):
    if request.method == 'POST' and 'logout' in request.POST:
        logout(request)  # Log out the user
        return redirect('login')  # Redirect to the login page after logout

    # Check if the user is authenticated
    if request.user.is_authenticated:
        username = request.user.username  # Get the username of the logged-in user
        return render(request, 'AtlantaFoodFinder/wassup.html', {'username': username})
    else:
        # Redirect to login if user is not logged in
        return redirect('login')

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



