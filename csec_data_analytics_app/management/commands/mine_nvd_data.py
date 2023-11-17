from django.core.management.base import BaseCommand
from csec_data_analytics_app.utilities.nvd_data_extractor import NVDDataExtractor

class Command(BaseCommand):
    help = 'Extract data from the National Vulnerability Database'

    def handle(self, *args, **options):
        try:
            # Instantiate the NVDDataExtractor
            nvd_extractor = NVDDataExtractor()

            # Call the extract_nvd_data method to initiate data extraction (e.g., for the past 120 days)
            nvd_extractor.extract_nvd_data(days=120)

            # Success message
            self.stdout.write(self.style.SUCCESS('Successfully extracted data from NVD.'))

        except Exception as e:
            # Error handling
            self.stderr.write(self.style.ERROR(f'Error occurred: {e}'))

            # Optionally, re-raise the exception if you want to stop the process
            # raise e
