from django.core.management.base import BaseCommand
from pymongo import MongoClient

class Command(BaseCommand):
    help = 'Integrate extracted features into MongoDB'

    def handle(self, *args, **options):
        client = MongoClient('mongodb://localhost:27017')
        db = client['django-mongo']
        collection = db['vulnerability']

        # Example data (replace with your actual data)
        extracted_features = [
            {'description': 'Description 1', 'extracted_data': 'Extracted Feature 1'},
            {'description': 'Description 2', 'extracted_data': 'Extracted Feature 2'},
            # Add more as needed
        ]

        for feature in extracted_features:
            filter_query = {'description': feature['description']}
            new_values = {
                "$set": {
                    'extracted_feature': feature['extracted_data'],
                    'validation_status': False
                }
            }

            collection.update_one(filter_query, new_values)

        client.close()
        self.stdout.write(self.style.SUCCESS('Successfully integrated extracted features into MongoDB'))
