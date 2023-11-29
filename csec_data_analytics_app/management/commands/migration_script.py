from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
import mongoengine
from mongoengine import Document, StringField, FloatField, ListField, connect, disconnect

# Correct database name and alias based on your MongoDB setup
db_name = 'django-mongo'
db_alias = 'default'

# Connect to the 'django-mongo' database
disconnect(alias=db_alias)
connect(alias=db_alias, db=db_name, host='mongodb://127.0.0.1:27017/' + db_name)

# Document class to match the structure of your 'vulnerabilities' collection
class Vulnerability(Document):
    # Define fields that match the structure of your MongoDB collection
    cve_id = StringField(primary_key=True)
    description = StringField()
    reported_date = StringField()  # Use DateTimeField if the date is stored in DateTime format
    severity = StringField()
    product = StringField()
    attack_vector = StringField()
    reported_date = DateTimeField()  # Changed from StringField to DateTimeField

    meta = {
        'collection': 'vulnerabilities',  # Make sure this is the correct collection name
        'db_alias': 'default'
    }

class Command(BaseCommand):
    help = 'Perform data analysis on vulnerabilities'

    def handle(self, *args, **kwargs):
        try:
            # Example query: Count vulnerabilities of Google Chrome in the past 120 days
            cutoff_date = datetime.now() - timedelta(days=120)
            chrome_vulns_count = Vulnerability.objects(
                product="Chrome",
                reported_date__gte=cutoff_date
            ).count()
            self.stdout.write(f'Number of Google Chrome vulnerabilities in the past 120 days: {chrome_vulns_count}')
        except mongoengine.errors.MongoEngineException as e:
            self.stderr.write(f'An error occurred: {e}')
