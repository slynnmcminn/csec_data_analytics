import requests
from typing import List, Dict

class NVDExtractor:
    """
    Utility class for extracting vulnerability data from the National Vulnerability Database (NVD).
    """

    def __init__(self, base_url: str = "https://services.nvd.nist.gov"):
        """
        Initialize the NVDExtractor.
        Parameters:
        - base_url (str): Base URL for the NVD API.
        """
        self.base_url = base_url

    def fetch_cve_details(self, cve_id: str) -> Dict:
        """
        Fetch details of a specific CVE (Common Vulnerabilities and Exposures) from NVD.
        Parameters:
        - cve_id (str): CVE ID of the vulnerability.
        Returns:
        - Dict: Details of the CVE.
        """
        endpoint = f"{self.base_url}/rest/json/cve/{cve_id}"
        response = requests.get(endpoint)
        if response.status_code == 200:
            return response.json()
        else:
            response.raise_for_status()

    def search_vulnerabilities(self, query: str) -> List[Dict]:
        """
        Search for vulnerabilities in NVD based on a query.
        Parameters:
        - query (str): Search query.
        Returns:
        - List[Dict]: List of vulnerabilities matching the query.
        """
        endpoint = f"{self.base_url}/rest/json/cves/1.0"
        params = {"keyword": query}
        response = requests.get(endpoint, params=params)
        if response.status_code == 200:
            return response.json().get("result", [])
        else:
            response.raise_for_status()

# Example Usage:
# nvd_extractor = NVDExtractor()
# cve_details = nvd_extractor.fetch_cve_details("CVE-2022-1234")
# vulnerabilities = nvd_extractor.search_vulnerabilities("python")
