#cisa_client.py
import requests
import logging
from csec_data_analytics_app.models import Vulnerability, CVEVulnerability, CVSSMetrics, VulnerableProduct, VulnerabilityImpact

class CISAClient:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def run(self):
        self.fetch_and_update_vulnerabilities()

    def fetch_and_update_vulnerabilities(self):
        try:
            response = requests.get(self.cisa_url)
            if response.status_code == 200:
                data = response.json()
                for item in data['vulnerabilities']:
                    cve_id = item.get('cveID')
                    if cve_id:
                        Vulnerability.objects(cve_id=cve_id).update_one(
                            set__exploitability_metric=item.get('exploitabilityMetric')
                        )
                        self.logger.info(f"Updated CVE ID {cve_id} with exploitability metric")
            else:
                self.logger.error(f"Failed to fetch CISA data: HTTP {response.status_code}")
        except requests.RequestException as e:
            self.logger.error(f"Request error occurred: {e}")

if __name__ == "__main__":
    try:
        cisa_client = CISAClient()
        cisa_client.run()
    except Exception as e:
        logging.error(f"An error occurred: {e}")
