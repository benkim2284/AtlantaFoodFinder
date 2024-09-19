from django.urls import path

from . import views
app_name = "AtlantaFoodFinder"

urlpatterns = [
    path("", views.IndexView.as_view(), name="index"),
    path("<int:pk>/", views.DetailView.as_view(), name="detail"),
    path("<int:pk>/results/", views.ResultsView.as_view(), name="results"),
    path("<int:question_id>/vote/", views.vote, name="vote"),
    path('map/', views.map_view, name='map'),  # Route for map view
    path('register/', views.register, name='register'),  # Route for register view
    path('login/', views.login_view, name='login'),  # Route for login view
]