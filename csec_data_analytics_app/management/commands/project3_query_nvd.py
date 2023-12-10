import requests
import json
from csec_data_analytics_app.models import Vulnerability, NVDClient
import logging
from django.core.management.base import BaseCommand
import csec_data_analytics_app.utilities.vulnerability_queries as vuln_queries

class Command(BaseCommand):
   help = 'Describes what your command does.'

   def handle(self, *args, **kwargs):
       nvd_client = NVDClient(delete_existing=True)
       nvd_client.run()
       vuln_queries.get_attack_vector_count(attack_vector='PHYSICAL')
       vuln_queries.get_attack_vector_count(attack_vector='NETWORK')
       vuln_queries.get_top_products_with_known_exploit(top_n=50)
       vuln_queries.get_vulnerabilities_for_product("chrome")

    vulnerabilities = fetch_vulnerabilities(start_date, end_date)
    for item in vulnerabilities:
        extracted_data = extract_vulnerability_data(item)
        # Now use extracted_data to create Vulnerability objects
        Vulnerability.objects.create(
            cve_id=extracted_data['cve_id'],
            description=extracted_data['description'],
            cvss_score=extracted_data['cvss_score'],
            attack_vector=extracted_data['attack_vector'],
            known_exploit=extracted_data['known_exploit'],
            vulnerable_products=["list", "of", "products"]  # Update this with actual data
        )