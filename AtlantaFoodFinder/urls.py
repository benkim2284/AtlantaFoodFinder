from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
app_name = "AtlantaFoodFinder"

urlpatterns = [
    #comment
    path("", views.home_view, name="index"),
    path("map/", views.map_view, name="map"),
    path('register/', views.register, name='register'),  # Route for register view
    path('login/', views.login_view, name='login'),  # Route for login view
    path('logout/', views.logout_view, name='logout'),
    path('password_reset/', views.password_reset_view, name='password_reset'),
    path('wassup/', views.wassup_view, name='wassup'),  # Route for login view
]
