# views.py
from django.shortcuts import render


def welcome_view(request):
    return render(request, "home.html")
