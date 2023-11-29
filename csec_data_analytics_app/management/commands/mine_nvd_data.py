from django.core.management.base import BaseCommand
from csec_data_analytics_app.management.commands.nvd_client import NVDClient

class Command(BaseCommand):
    help = 'Mine data from the National Vulnerability Database (NVD) and store it in the database'

    def handle(self, *args, **kwargs):
        nvd_client = NVDClient(delete_existing=True)
        nvd_client.run()
