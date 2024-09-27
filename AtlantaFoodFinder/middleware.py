from django.shortcuts import redirect
from django.urls import reverse

class AuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        print(f"Requested path: {request.path}")
        print(f"User authenticated: {request.user.is_authenticated}")

        excluded_paths = [
            "/AtlantaFoodFinder/login/",  # Ensure you have the correct name for the login view
            '/AtlantaFoodFinder/register/', # Ensure you have the correct name for the registration view
            '/AtlantaFoodFinder/',
        ]

        # Check if the user is authenticated
        if not request.user.is_authenticated and request.path not in excluded_paths:
            return redirect('AtlantaFoodFinder:login')  # Redirect to the login page

            # If authenticated or path is excluded, continue processing the request
        response = self.get_response(request)
        return response
