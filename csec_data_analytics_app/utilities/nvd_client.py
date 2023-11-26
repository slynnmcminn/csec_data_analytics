# nvd_client.py
import os
import django
import requests
from datetime import datetime, timedelta
from mongoengine import connect, disconnect
from csec_data_analytics_app.models import Vulnerability, CVSSMetrics, CVEVulnerability, VulnerableProduct, VulnerabilityImpact


class NVDClient:
    MAX_RESULTS_PER_REQUEST = 2000

    def __init__(self, delete_existing=False):
        # Initialize the NVDClient with optional deletion of existing data
        current_date = datetime.utcnow()
        start_date = current_date - timedelta(days=120)
        self.api_url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
        self.nvd_api_key = os.environ.get('NVD_API_KEY')
        self.headers = {'ApiKey': self.nvd_api_key}
        self.params = {
            'resultsPerPage': self.MAX_RESULTS_PER_REQUEST,
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S:000 UTC'),
            'pubEndDate': current_date.strftime('%Y-%m-%dT%H:%M:%S:000 UTC')
        }
        if delete_existing:
            # Clear existing data if specified
            Vulnerability.objects.delete()

    def run(self):
        # Entry point to start fetching and storing vulnerabilities
        self.fetch_and_store_vulnerabilities()

    def fetch_and_store_vulnerabilities(self):
        next_index = 0
        fetch_next = True
        while fetch_next:
            response = requests.get(self.api_url, headers=self.headers, params=self.params)
            if response.status_code != 200:
                response.raise_for_status()

            data = response.json()
            total_results = data['totalResults']
            next_index += self.MAX_RESULTS_PER_REQUEST
            fetch_next = next_index < total_results

            for item in data.get('result', {}).get('CVE_Items', []):
                self.process_and_store_data(item)

    def process_and_store_data(self, item):
        try:
            # Extract relevant data from the CVE item
            cve_id = item['cve']['CVE_data_meta']['ID']

            # Check if description_data exists and has the 'value' field
            description_data = item['cve']['description']['description_data']
            if description_data and 'value' in description_data[0]:
                description = description_data[0]['value']
            else:
                description = "No description available"  # Default description
            # Check if cpe_configurations exists
            cpe_configurations = item.get('configurations', {}).get('nodes', [])
            if not cpe_configurations:
                print(f"Warning: No cpe_configurations available for CVE ID {cve_id}")
                return  # Skip this entry and continue processing the next one

            cwes = [problem['description'] for problem in
                    item['cve']['problemtype']['problemtype_data'][0]['description']]

            impact_data = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
            cvss_score = impact_data.get('baseScore', 0)

            cvss_vector = impact_data.get('vectorString', '')
            attack_vector = impact_data.get('attackVector', '')
            attack_complexity = impact_data.get('attackComplexity', '')
            privileges_required = impact_data.get('privilegesRequired', '')
            user_interaction = impact_data.get('userInteraction', '')
            scope = impact_data.get('scope', '')
            confidentiality_impact = impact_data.get('confidentialityImpact', '')
            integrity_impact = impact_data.get('integrityImpact', '')
            availability_impact = impact_data.get('availabilityImpact', '')
            exploitability_score = impact_data.get('exploitabilityScore', 0)

            # Create or update the vulnerability document in the database
            Vulnerability.objects(cve_id=cve_id).update_one(
                upsert=True,
                set__description=description,
                set__cpe_configurations=cpe_configurations,
                set__cwes=cwes,
                set__cvss_score=cvss_score,
                set__cvss_vector=cvss_vector,
                set__attack_vector=attack_vector,
                set__attack_complexity=attack_complexity,
                set__privileges_required=privileges_required,
                set__user_interaction=user_interaction,
                set__scope=scope,
                set__confidentiality_impact=confidentiality_impact,
                set__integrity_impact=integrity_impact,
                set__availability_impact=availability_impact,
                set__exploitability_score=exploitability_score
            )
        except Exception as e:
            print(f"Error processing CVE ID {cve_id}: {e}")
        except KeyError as e:
            print(f"Missing key {e} while processing CVE ID {cve_id}")
        except ValueError as e:
            print(e)

if __name__ == "__main__":
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'csec_data_analytics.settings')
    django.setup()

    disconnect()
    connect('django-mongo', host='localhost', port=27017)

    # Initialize NVDClient with the option to delete existing data
    nvd_client = NVDClient(delete_existing=True)
    nvd_client.run()

    disconnect()
