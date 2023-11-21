from django.core.management.base import BaseCommand
from csec_data_analytics_app.models import Vulnerability
from datetime import datetime, timedelta

class Command(BaseCommand):
    help = 'Identify the most common CWE from the past year'

    def handle(self, *args, **kwargs):
        nvd_client = NVDClient(delete_existing=True)
        nvd_client.run()
        one_year_ago = datetime.now() - timedelta(days=365)
        pipeline = [
            {'$match': {'date_published': {'$gte': one_year_ago}}},
            {'$unwind': '$cwes'},
            {'$group': {'_id': '$cwes', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 1}
        ]
        most_common_cwe = list(Vulnerability.objects.aggregate(*pipeline))
        if most_common_cwe:
            self.stdout.write(f"The most common CWE last year was: {most_common_cwe[0]['_id']} with {most_common_cwe[0]['count']} occurrences.")
        else:
            self.stdout.write("No data available for the past year.")
