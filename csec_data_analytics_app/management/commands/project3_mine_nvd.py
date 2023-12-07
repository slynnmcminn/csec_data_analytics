from django.core.management.base import BaseCommand
from csec_data_analytics_app.utilities.nvd_client import NVDClient

class Command(BaseCommand):
    help = 'Describes what your command does.'

    def handle(self, *args, **kwargs):
        nvd_client = NVDClient(delete_existing=True)  # or False, depending on your need
        nvd_client.run()
        self.stdout.write(self.style.SUCCESS('Successfully fetched and stored vulnerabilities.'))
