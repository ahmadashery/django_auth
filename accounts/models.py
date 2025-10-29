from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class GoogleAnalyticsToken(models.Model):
    """
    Store Google Analytics OAuth tokens for each user.
    """

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="ga_token")
    access_token = models.TextField()
    refresh_token = models.TextField()
    token_uri = models.CharField(
        max_length=255, default="https://oauth2.googleapis.com/token"
    )
    client_id = models.CharField(max_length=255)
    client_secret = models.CharField(max_length=255)
    scopes = models.JSONField(default=list)
    expiry = models.DateTimeField(null=True, blank=True)

    # Selected GA4 property
    selected_property_id = models.CharField(max_length=255, null=True, blank=True)
    selected_property_name = models.CharField(max_length=255, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"GA Token for {self.user.username}"

    def is_expired(self):
        """Check if the token is expired."""
        if not self.expiry:
            return True
        return timezone.now() >= self.expiry

    class Meta:
        verbose_name = "Google Analytics Token"
        verbose_name_plural = "Google Analytics Tokens"
