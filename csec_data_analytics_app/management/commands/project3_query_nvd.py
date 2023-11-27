from django.core.management.base import BaseCommand
from datetime import datetime, timedelta
from csec_data_analytics_app.models import Vulnerability
from csec_data_analytics_app.management.commands.vulnerability_queries_helpers import (
    get_vulnerabilities_for_product,
    get_attack_vector_count,
    get_most_common_weakness_last_year,
    get_top_vendor_with_known_exploits_last_year
)

class Command(BaseCommand):
    help = 'Run queries against the NVD data'

    def handle(self, *args, **options):
        self.query_google_chrome_vulnerabilities()  # Corrected method name
        get_attack_vector_count('NETWORK')
        get_attack_vector_count('PHYSICAL')
        get_top_vendor_with_known_exploits_last_year()
        get_most_common_weakness_last_year()
        self.query_total_vulnerabilities()

    def query_google_chrome_vulnerabilities(self):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=120)
        get_vulnerabilities_for_product("Chrome")

    def query_total_vulnerabilities(self):
        count = Vulnerability.objects.count()
        self.stdout.write(f'Total number of vulnerabilities (simple count): {count}')
