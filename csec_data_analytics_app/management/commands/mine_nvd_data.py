from django.core.management.base import BaseCommand
from csec_data_analytics_app.utilities.nvd_client import NVDClient

class Command(BaseCommand):
    help = 'Extract data from the National Vulnerability Database and store in MongoDB.'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting NVD data extraction...'))
        nvd_client = NVDClient()
        nvd_client.run()
        self.stdout.write(self.style.SUCCESS('NVD data extraction completed.'))
