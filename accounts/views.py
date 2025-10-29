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


from .models import GoogleAnalyticsToken

# ============================================
# Google Analytics OAuth Views
# ============================================


# Path to your OAuth credentials (downloaded from Google Cloud Console)
GOOGLE_CREDENTIALS_FILE = os.path.join(os.path.dirname(__file__), "credentials.json")

SCOPES = [
    "https://www.googleapis.com/auth/analytics.readonly",
    "https://www.googleapis.com/auth/userinfo.profile",
]
REDIRECT_URI = "http://localhost:8000/accounts/google/callback/"


@login_required
def connect_google_analytics(request):
    """
    Initiate Google Analytics OAuth flow.
    """
    flow = Flow.from_client_secrets_file(
        GOOGLE_CREDENTIALS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI
    )

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",  # Force to get refresh token
    )

    # Store state in session for security
    request.session["oauth_state"] = state

    return redirect(authorization_url)


@login_required
def google_callback(request):
    """
    Handle Google OAuth callback and store tokens.
    """
    state = request.session.get("oauth_state")

    flow = Flow.from_client_secrets_file(
        GOOGLE_CREDENTIALS_FILE, scopes=SCOPES, state=state, redirect_uri=REDIRECT_URI
    )

    # Get the authorization response
    authorization_response = request.build_absolute_uri()
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials

    # Load client secrets to get client_id and client_secret
    with open(GOOGLE_CREDENTIALS_FILE, "r") as f:
        client_config = json.load(f)

        # Handle both 'web' and 'installed' credential types
        if "web" in client_config:
            client_id = client_config["web"]["client_id"]
            client_secret = client_config["web"]["client_secret"]
        elif "installed" in client_config:
            client_id = client_config["installed"]["client_id"]
            client_secret = client_config["installed"]["client_secret"]
        else:
            # If neither, try to get directly from root
            client_id = client_config.get("client_id")
            client_secret = client_config.get("client_secret")

    # Debug print
    print(f"Saving token for user: {request.user.username}")
    print(f"Has refresh token: {credentials.refresh_token is not None}")
    print(f"Access token exists: {credentials.token is not None}")

    # Save or update token in database
    ga_token, created = GoogleAnalyticsToken.objects.update_or_create(
        user=request.user,
        defaults={
            "access_token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "scopes": credentials.scopes,
            "expiry": credentials.expiry,
        },
    )

    print(f"Token saved. Created: {created}")

    return redirect("/")


@login_required
def disconnect_google_analytics(request):
    """
    Disconnect Google Analytics account.
    """
    try:
        ga_token = GoogleAnalyticsToken.objects.get(user=request.user)
        ga_token.delete()
        return JsonResponse(
            {"success": True, "message": "Google Analytics disconnected"}
        )
    except GoogleAnalyticsToken.DoesNotExist:
        return JsonResponse(
            {"success": False, "message": "No connection found"}, status=404
        )


def get_or_refresh_credentials(user):
    """
    Get credentials for a user, refreshing if necessary.
    """
    try:
        ga_token = GoogleAnalyticsToken.objects.get(user=user)
        print(f"Found token for user: {user.username}")
    except GoogleAnalyticsToken.DoesNotExist:
        print(f"No token found for user: {user.username}")
        return None

    # Check if we have required fields
    if not ga_token.access_token or not ga_token.refresh_token:
        print(
            f"Missing tokens - access: {bool(ga_token.access_token)}, refresh: {bool(ga_token.refresh_token)}"
        )
        return None

    print("Creating credentials object")
    credentials = Credentials(
        token=ga_token.access_token,
        refresh_token=ga_token.refresh_token,
        token_uri=ga_token.token_uri,
        client_id=ga_token.client_id,
        client_secret=ga_token.client_secret,
        scopes=ga_token.scopes,
    )

    # Refresh token if expired
    if ga_token.is_expired():
        print("Token expired, refreshing...")
        try:
            from google.auth.transport.requests import Request

            credentials.refresh(Request())

            # Update token in database
            ga_token.access_token = credentials.token
            ga_token.expiry = credentials.expiry
            ga_token.save()
            print("Token refreshed successfully")
        except Exception as e:
            print(f"Error refreshing token: {e}")
            return None
    else:
        print("Token still valid")

    return credentials


@login_required
def list_ga4_properties(request):
    """
    View that lists all Google Analytics 4 properties for the authenticated account.
    """
    print(f"list_ga4_properties called by user: {request.user.username}")

    try:
        credentials = get_or_refresh_credentials(request.user)

        if not credentials:
            print("Credentials are None!")
            return JsonResponse(
                {
                    "error": "Google Analytics not connected. Please reconnect.",
                    "connected": False,
                },
                status=400,
            )

        print("Creating AnalyticsAdminServiceClient...")
        client = AnalyticsAdminServiceClient(credentials=credentials)

        print("Calling list_account_summaries...")
        # Use list_account_summaries - this works without filters
        account_summaries = client.list_account_summaries()

        all_properties = []

        print("Processing account summaries...")
        for summary in account_summaries:
            print(
                f"Found account: {summary.account if hasattr(summary, 'account') else 'Unknown'}"
            )
            if hasattr(summary, "property_summaries"):
                for prop_summary in summary.property_summaries:
                    print(f"  - Property: {prop_summary.display_name}")
                    all_properties.append(
                        {
                            "property_name": prop_summary.display_name,
                            "property_id": prop_summary.property,
                            "account_name": (
                                summary.display_name
                                if hasattr(summary, "display_name")
                                else summary.account
                            ),
                        }
                    )

        print(f"Total properties found: {len(all_properties)}")
        return JsonResponse(
            {"properties": all_properties, "connected": True}, status=200
        )

    except Exception as e:
        import traceback

        error_trace = traceback.format_exc()
        print(f"Error in list_ga4_properties: {e}")
        print(error_trace)
        return JsonResponse({"error": str(e), "traceback": error_trace}, status=500)


@login_required
def check_ga_connection(request):
    """
    Check if user has connected Google Analytics.
    """
    try:
        ga_token = GoogleAnalyticsToken.objects.get(user=request.user)
        return JsonResponse(
            {
                "connected": True,
                "has_refresh_token": bool(ga_token.refresh_token),
                "token_exists": bool(ga_token.access_token),
            }
        )
    except GoogleAnalyticsToken.DoesNotExist:
        return JsonResponse({"connected": False})
