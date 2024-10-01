from django.shortcuts import redirect
from django.urls import reverse

class AuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        print(f"Requested path: {request.path}")
        print(f"User authenticated: {request.user.is_authenticated}")
        if request.path == "/":
            return redirect('AtlantaFoodFinder:index')

        excluded_paths = [
            "/AtlantaFoodFinder/login/",
            '/AtlantaFoodFinder/register/',
            '/AtlantaFoodFinder/password_reset/',
            '/AtlantaFoodFinder/',
        ]

        if not request.user.is_authenticated and request.path not in excluded_paths:
            return redirect('AtlantaFoodFinder:login')

        response = self.get_response(request)
        return response
