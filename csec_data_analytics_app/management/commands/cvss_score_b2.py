import requests
from datetime import datetime, timedelta
import json
from django.core.management.base import BaseCommand
from csec_data_analytics_app.utilities.nvd_client import NVDClient
from csec_data_analytics_app.models import Vulnerability

class Command(BaseCommand):
    help = 'Fetch and display CVSS scores and other vulnerability data from NVD.'

    def handle(self, *args, **options):
        nvd_client = NVDClient(delete_existing=True)
        nvd_client.run()

        data = []  # Initialize data as an empty list
        for vuln in Vulnerability.objects.all()[:100]:  # Adjust as needed
            risk_level = self.calculate_risk_level(vuln.cvss_score)
            data.append({
                'CVE ID': vuln.cve_id,
                'Description': vuln.description,
                'Attack Vector': vuln.attack_vector,
                'Known Exploit': vuln.known_exploit,
                'CVSS Score': vuln.cvss_score,
                'Risk Level': risk_level
            })
            self.stdout.write(f"CVE ID: {vuln.cve_id}, CVSS Score: {vuln.cvss_score}, Description: {vuln.description}")

    def calculate_risk_level(self, cvss_score):
        if cvss_score is None:
            return 'Unknown'
        elif cvss_score <= 3.9:
            return 'Low'
        elif cvss_score <= 6.9:
            return 'Medium'
        else:
            return 'High'
