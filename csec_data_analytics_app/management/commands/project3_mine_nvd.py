from django.core.management.base import BaseCommand
from csec_data_analytics_app.utilities.nvd_client import NVDClient
from django.conf import settings
from mongoengine import connect, disconnect
from csec_data_analytics_app.models import Vulnerability

help = 'Fetches data from NVD and stores in MongoDB.'

def handle(self, *args, **kwargs):
    # Connect to MongoDB using settings from settings.py
    connect(host=settings.MONGO_DB_URI, alias='default')

    # Rest of your code to fetch and store data
    nvd_client = NVDClient(delete_existing=True)
    nvd_client.run()

    vulnerabilities = Vulnerability.objects.all()
    if not vulnerabilities:
        print("No data found in the Vulnerability collection")
    else:
        print(f"Found {len(vulnerabilities)} records in the Vulnerability collection")
