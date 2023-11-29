# top_vendor_query.py

from django.core.management.base import BaseCommand
from csec_data_analytics_app.models import Vulnerability
from datetime import datetime

class Command(BaseCommand):
    help = 'Query for the vendor with the most known exploits last year'

    def handle(self, *args, **options):
        last_year = datetime.now().year - 1
        start_last_year = datetime(last_year, 1, 1)
        end_last_year = datetime(last_year, 12, 31)

        pipeline = [
            {"$match": {
                "known_exploit": True,
                "publishedDate": {"$gte": start_last_year, "$lte": end_last_year}
            }},
            {"$unwind": "$vulnerable_products"},
            {"$group": {
                "_id": "$vulnerable_products.vendor",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 1}
        ]

        results = list(Vulnerability.objects().aggregate(*pipeline))
        if results:
            top_vendor = results[0]
            self.stdout.write(f"The vendor with the most known exploits last year is '{top_vendor['_id']}' with {top_vendor['count']} known exploits.")
        else:
            self.stdout.write("No vendor with known exploits found for last year.")
