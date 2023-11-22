from django.core.management.base import BaseCommand
from csec_data_analytics_app.models import CVEVulnerability, Vulnerability
from datetime import datetime, timedelta

class Command(BaseCommand):
    help = 'Run queries against the NVD data'

    def handle(self, *args, **options):
        self.query_google_chrome_vulnerabilities()
        self.query_attack_vector_count('NETWORK')
        self.query_attack_vector_count('PHYSICAL')
        self.query_top_vendor_known_exploits()
        self.query_most_common_weakness()

    def query_google_chrome_vulnerabilities(self):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=120)
        count = CVEVulnerability.objects(
            vulnerabilities__product='chrome',
            publishedDate__gte=start_date,
            publishedDate__lte=end_date
        ).count()
        self.stdout.write(f"Google Chrome vulnerabilities in the past 120 days: {count}")

    def query_attack_vector_count(self, attack_vector):
        count = Vulnerability.objects(attack_vector=attack_vector).count()
        self.stdout.write(f"Vulnerabilities with the attack vector {attack_vector}: {count}")

    def query_top_vendor_known_exploits(self):
        last_year = datetime.now().year - 1
        pipeline = [
            {"$unwind": "$vulnerable_products"},
            {"$match": {
                "known_exploit": True,
                "publishedDate": {"$gte": datetime(last_year, 1, 1), "$lte": datetime(last_year, 12, 31)}
            }},
            {"$group": {
                "_id": "$vulnerable_products.vendor",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 1}
        ]
        result = list(Vulnerability.objects().aggregate(*pipeline))
        if result:
            top_vendor, count = result[0]['_id'], result[0]['count']
            self.stdout.write(f"Top vendor with known exploits last year: {top_vendor} ({count} exploits)")

    def query_most_common_weakness(self):
        last_year = datetime.now().year - 1
        pipeline = [
            {"$unwind": "$cwes"},
            {"$match": {
                "publishedDate": {"$gte": datetime(last_year, 1, 1), "$lte": datetime(last_year, 12, 31)}
            }},
            {"$group": {
                "_id": "$cwes",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 1}
        ]
        result = list(Vulnerability.objects().aggregate(*pipeline))
        if result:
            most_common_cwe, count = result[0]['_id'], result[0]['count']
            self.stdout.write(f"Most common weakness last year: {most_common_cwe} (Count: {count})")
