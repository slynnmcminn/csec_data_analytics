from django.core.management.base import BaseCommand
from csec_data_analytics.settings import NVD_API_KEY
from csec_data_analytics_app.utilities.nvd_data_extractor import \
    NVDDataExtractor  # Correct import path
class Command(BaseCommand):
    help = 'Extract data from the National Vulnerability Database'

    def handle(self, *args, **options):
        # Instantiate the NVDDataExtractor
        nvd_extractor = NVDDataExtractor()

        # Call the extract_nvd_data method to initiate data extraction (e.g., for the past 120 days)
        nvd_extractor.extract_nvd_data(days=120)

