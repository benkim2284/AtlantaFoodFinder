from django import forms
from django.contrib.auth.models import User


class RegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']


from .models import Review
from django.core.validators import MinLengthValidator, MaxLengthValidator

class ReviewForm(forms.ModelForm):
    review_text = forms.CharField(
        widget=forms.Textarea,
        validators=[
            MinLengthValidator(10),
            MaxLengthValidator(2000)
        ]
    )
    rating = forms.IntegerField(min_value=1, max_value=5)

    class Meta:
        model = Review
        fields = ['rating', 'review_text']

    def clean_review_text(self):
        review_text = self.cleaned_data.get('review_text')
        if not review_text.strip():
            raise forms.ValidationError("Review cannot be blank or whitespace.")
        return review_text