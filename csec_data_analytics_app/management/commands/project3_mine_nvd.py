from django.core.management.base import BaseCommand
from csec_data_analytics_app.utilities.nvd_client import NVDClient
from django.conf import settings
from mongoengine import connect, disconnect
from csec_data_analytics_app.models import Vulnerability

class Command(BaseCommand):
    help = 'Describes what your command does.'

    def handle(self, *args, **kwargs):
        print("Database settings:", settings.DATABASES)
        nvd_client = NVDClient(delete_existing=True)
        nvd_client.run()

        # Connect to MongoDB
        disconnect()
        connect('django-mongo')

        # Attempt to fetch data
        vulnerabilities = Vulnerability.objects.all()
        if not vulnerabilities:
            print("No data found in the Vulnerability collection")
        else:
            print(f"Found {len(vulnerabilities)} records in the Vulnerability collection")
