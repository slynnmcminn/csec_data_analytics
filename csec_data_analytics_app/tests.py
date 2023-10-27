from django.test import TestCase
from .models import Vulnerability  # Import your model

class VulnerabilityTestCase(TestCase):
    def setUp(self):
        # Create test data
        self.vulnerability = Vulnerability.objects.create(
            title="Test Vulnerability",
            description="This is a test vulnerability.",
            severity="High",
            published_date="2023-10-26",
            # Add other fields as needed
        )

    def test_vulnerability_title(self):
        # Test the title of the vulnerability
        self.assertEqual(self.vulnerability.title, "Test Vulnerability")

    def test_vulnerability_severity(self):
        # Test the severity of the vulnerability
        self.assertEqual(self.vulnerability.severity, "High")

    # Add more test methods as needed
