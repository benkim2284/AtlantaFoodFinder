from django.urls import path

from . import views
app_name = "AtlantaFoodFinder"

urlpatterns = [
    path("", views.IndexView.as_view(), name="index"),
    path('register/', views.register, name='register'),  # Route for register view
    path('login/', views.login_view, name='login'),  # Route for login view
    path('home/', views.home_view, name='home'),  # Route for login view
]
