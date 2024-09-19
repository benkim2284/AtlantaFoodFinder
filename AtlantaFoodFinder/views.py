from django.db.models import F
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views import generic

from .models import Choice, Question
from django.utils import timezone
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from .forms import RegisterForm
from django.contrib.auth.models import User



class IndexView(generic.ListView):
    template_name = "AtlantaFoodFinder/index.html"
    context_object_name = "latest_question_list"

    def get_queryset(self):
        """Return the last five published questions."""
        return Question.objects.filter(pub_date__lte=timezone.now()).order_by("-pub_date")[:5]


class DetailView(generic.DetailView):
    model = Question
    template_name = "AtlantaFoodFinder/detail.html"

    def get_queryset(self):
        """
        Excludes any questions that aren't published yet.
        """
        return Question.objects.filter(pub_date__lte=timezone.now())


class ResultsView(generic.DetailView):
    model = Question
    template_name = "AtlantaFoodFinder/results.html"

def vote(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    try:
        selected_choice = question.choice_set.get(pk=request.POST["choice"])
    except (KeyError, Choice.DoesNotExist):
        # Redisplay the question voting form.
        return render(
            request,
            "AtlantaFoodFinder/detail.html",
            {
                "question": question,
                "error_message": "You didn't select a choice.",
            },
        )

    else:
        selected_choice.votes = F("votes") + 1
        selected_choice.save()
        # Always return an HttpResponseRedirect after successfully dealing
        # with POST data. This prevents data from being posted twice if a
        # user hits the Back button.
        return HttpResponseRedirect(reverse("AtlantaFoodFinder:results", args=(question.id,)))


def map_view(request):
    context = {
        'lat': -25.363,
        'lng': 131.044
    }
    return render(request, 'map.html', context)


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
            return redirect('AtlantaFoodFinder:home')
        else:
            return render(request, 'AtlantaFoodFinder/login.html', {'error': 'Invalid credentials'})
    else:
        return render(request, 'AtlantaFoodFinder/login.html')


def home_view(request):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        username = request.user.username  # Get the username of the logged-in user
        return render(request, 'AtlantaFoodFinder/home.html', {'username': username})
    else:
        # Redirect to login if user is not logged in
        return redirect('login')
