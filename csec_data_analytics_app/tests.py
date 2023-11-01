from django.test import TestCase
from rest_framework.test import APIClient
from .models import Vulnerability

class VulnerabilityTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()  # Initialize an API client for testing

        # Create test data
        self.vulnerability_data = {
            "title": "Test Vulnerability",
            "description": "This is a test vulnerability.",
            "severity": "High",
            "published_date": "2023-10-26",
            # Add other fields as needed
        }

        # Create a Vulnerability instance for testing
        self.vulnerability = Vulnerability.objects.create(**self.vulnerability_data)

    def test_vulnerability_title(self):
        # Test the title of the vulnerability
        self.assertEqual(self.vulnerability.title, "Test Vulnerability")

    def test_vulnerability_severity(self):
        # Test the severity of the vulnerability
        self.assertEqual(self.vulnerability.severity, "High")

    def test_create_vulnerability(self):
        # Test creating a new vulnerability using the API
        response = self.client.post("/api/vulnerabilities/", self.vulnerability_data, format="json")
        self.assertEqual(response.status_code, 201)  # Check if the response is HTTP 201 (Created)

        # Optionally, you can also check the created data in the response, e.g., response.data['title']

    # Add more test methods as needed
