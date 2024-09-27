from django.urls import path

from . import views
app_name = "AtlantaFoodFinder"

urlpatterns = [
    path("", views.home_view, name="home"),
    path("map/", views.map_view, name="map"),
    path('register/', views.register, name='register'),  # Route for register view
    path('login/', views.login_view, name='login'),  # Route for login view
    path('wassup/', views.wassup_view, name='wassup'),  # Route for login view
]
