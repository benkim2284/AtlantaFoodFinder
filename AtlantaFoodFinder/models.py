import datetime

from django.contrib import admin
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


# Create your models here.
class Question(models.Model):
    question_text = models.CharField(max_length=200)
    pub_date = models.DateTimeField("date published")
    def __str__(self):
        return self.question_text

    @admin.display(
        boolean=True,
        ordering="pub_date",
        description="Published recently?",
    )
    def was_published_recently(self):
        now = timezone.now()
        return now - datetime.timedelta(days=1) <= self.pub_date <= now

class Choice(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    choice_text = models.CharField(max_length=200)
    votes = models.IntegerField(default=0)

    def __str__(self):
        return self.choice_text


class Favorite(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    place_id = models.CharField(max_length=100)
    name = models.CharField(max_length=100)
    location = models.CharField(max_length=200)
    formatted_address = models.CharField(max_length=300)
    date_added = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'{self.name} ({self.formatted_address})'
