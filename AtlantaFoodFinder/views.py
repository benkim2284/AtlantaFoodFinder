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
from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator, MaxLengthValidator

from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib import messages


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

def logout_view(request):
    logout(request)
    return redirect('AtlantaFoodFinder:login')


def wassup_view(request):
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