# mine_cisa_data.py
from django.core.management.base import BaseCommand
from csec_data_analytics_app.management.commands.cisa_client import CISAClient

class Command(BaseCommand):
    help = 'Extract data from the Department of Homeland Security CISA'

    def handle(self, *args, **options):
        cisa_client = CISAClient()
        cisa_client.run()
        self.stdout.write(self.style.SUCCESS('Successfully extracted and updated CISA data.'))
