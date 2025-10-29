import os
import json

from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import redirect, render
from google.analytics.admin import AnalyticsAdminServiceClient
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


# ============================================
# Django Authentication Views
# ============================================


def register_view(request):
    """
    View for user registration.
    """
    if request.user.is_authenticated:
        return redirect("/")

    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Specify the backend explicitly
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            return redirect("/")
    else:
        form = UserCreationForm()

    return render(request, "registration/register.html", {"form": form})


def login_view(request):
    """
    View for user login.
    """
    if request.user.is_authenticated:
        return redirect("/")

    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:
                # Specify the backend explicitly
                login(
                    request, user, backend="django.contrib.auth.backends.ModelBackend"
                )
                return redirect("/")
    else:
        form = AuthenticationForm()

    return render(request, "registration/login.html", {"form": form})


@login_required
def logout_view(request):
    """
    View for logging out.
    """
    logout(request)
    return redirect("/")


# ============================================
# Utility Views
# ============================================


def check_auth(request):
    """
    Check if user is authenticated.
    """
    if request.user.is_authenticated:
        return JsonResponse({"authenticated": True})
    else:
        return JsonResponse({"authenticated": False}, status=403)


def get_csrf_token(request):
    """
    Get CSRF token.
    """
    return JsonResponse({"csrfToken": get_token(request)})
