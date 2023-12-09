from django.core.management.base import BaseCommand
import requests
from mongoengine import connect, disconnect, connection
from csec_data_analytics_app.models import Vulnerability
# ... other imports ...

class Command(BaseCommand):
    help = 'Updates vulnerabilities with CVSS scores from NVD and trains a model.'

    def handle(self, *args, **kwargs):
        self.update_vulnerabilities_with_cvss()
        # ... rest of your existing code to process and export data ...

    def update_vulnerabilities_with_cvss(self):
        if not connection.get_connection():
            connect('django-mongo')

        try:
            for vuln in Vulnerability.objects.all():
                if vuln.cvss_score is None:  # Assuming 'cvss_score' is a field in your model
                    cvss_score = self.fetch_cvss_score(vuln.cve_id)
                    if cvss_score:
                        vuln.update(set__cvss_score=cvss_score)
        finally:
            if connection.get_connection():
                disconnect()

    def fetch_cvss_score(self, cve_id):
        url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            cvss_score = data.get('result', {}).get('CVE_Items', [])[0].get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore')
            return cvss_score
        return None
