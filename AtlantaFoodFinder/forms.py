from django import forms
from django.contrib.auth.models import User
from django.core.validators import MinLengthValidator, MaxLengthValidator
from .models import Review


class RegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']


class ReviewForm(forms.ModelForm):
    review_text = forms.CharField(
        widget=forms.Textarea,
        validators=[
            MinLengthValidator(10),  # Minimum length of 10 characters
            MaxLengthValidator(2000)   # Maximum length of 2000 characters
        ]
    )
    rating = forms.IntegerField(min_value=1, max_value=5)  # Rating must be between 1 and 5

    class Meta:
        model = Review
        fields = ['rating', 'review_text']

    def clean_review_text(self):
        review_text = self.cleaned_data.get('review_text')

        # Check for blank or all-whitespace review
        if not review_text.strip():
            raise forms.ValidationError("Review cannot be blank or whitespace.")

        # Check for extremely large reviews (already limited by MaxLengthValidator)
        # Here, you can add any additional logic if you want a stricter limit
        if len(review_text) > 2000:
            raise forms.ValidationError("Review is too long. Maximum 2000 characters allowed.")

        return review_text
