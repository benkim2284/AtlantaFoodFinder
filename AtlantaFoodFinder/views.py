from django.db.models import F
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views import generic

from .models import Choice, Question
from django.utils import timezone
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import RegisterForm
from django.contrib.auth.models import User


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

