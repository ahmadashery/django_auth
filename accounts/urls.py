from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView


# Create a GoogleLogin class to handle the Google OAuth login
class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    callback_url = "http://localhost:8000/accounts/dj-rest-auth/google/"
    client_class = OAuth2Client


# Import required libraries for settings urls
from django.urls import path
from . import views

# Urls for accounts app
urlpatterns = [
    # Django Authentication
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("check-auth/", views.check_auth, name="check_auth"),
    path("get-csrf-token/", views.get_csrf_token, name="get_csrf_token"),
    # Google Analytics OAuth
    path("connect-google/", views.connect_google_analytics, name="connect_google"),
    path("google/callback/", views.google_callback, name="google_callback"),
    path(
        "disconnect-google/",
        views.disconnect_google_analytics,
        name="disconnect_google",
    ),
    path("check-ga-connection/", views.check_ga_connection, name="check_ga_connection"),
    path("ga4-properties/", views.list_ga4_properties, name="list_ga4_properties"),
]
