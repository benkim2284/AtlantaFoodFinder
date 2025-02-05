from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
app_name = "AtlantaFoodFinder"

urlpatterns = [
    path("", views.home_view, name="index"),
    path("map/", views.map_view, name="map"),
    path('register/', views.register, name='register'),  # Route for register view
    path('login/', views.login_view, name='login'),  # Route for login view
    path('api/logout/', views.logout_view, name='logout'),
    path('password_reset/', views.password_reset_view, name='password_reset'),
    path('api/add_favorite/', views.add_favorite_place, name='add_favorite'),  # Route for login view
    path('api/get_favorites/', views.get_favorites, name='get_favorites'),  # Route for login view
    path('api/remove_favorite/', views.remove_favorite, name='remove_favorite'),  # Route for login view
    path('api/check_add_restaurant/', views.check_add_restaurant, name='check_add_restaurant'),


    path('restaurants/<str:restaurant_hash>/', views.restaurant_detail, name='restaurant_detail'),
    path('restaurants/<str:restaurant_hash>/add_review/', views.add_review, name='add_review'),
    path('users/<str:username>/reviews/', views.user_reviews, name='user_reviews'),
]
