from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
app_name = "AtlantaFoodFinder"

urlpatterns = [
    path("", views.home_view, name="index"),
    path("map/", views.map_view, name="map"),
    path('register/', views.register, name='register'),  # Route for register view
    path('login/', views.login_view, name='login'),  # Route for login view
    path('logout/', views.logout_view, name='logout'),
    path('password_reset/', views.password_reset_view, name='password_reset'),
    path('wassup/', views.wassup_view, name='wassup'),  # Route for login view
    path('restaurants/', views.restaurant_list, name='restaurant_list'),
    path('restaurants/<int:restaurant_id>/', views.restaurant_detail, name='restaurant_detail'),
    path('restaurants/<int:restaurant_id>/add_review/', views.add_review, name='add_review'),
    path('users/<str:username>/reviews/', views.user_reviews, name='user_reviews'),

]
