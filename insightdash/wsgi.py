import os

# Import Django libraries
from django.core.wsgi import get_wsgi_application

# Set the default Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "insightdash.settings")

application = get_wsgi_application()
