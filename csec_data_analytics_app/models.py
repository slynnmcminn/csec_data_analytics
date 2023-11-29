import re
from datetime import datetime
from mongoengine import Document, StringField, ListField, EmbeddedDocument, EmbeddedDocumentField, BooleanField, DateTimeField, FloatField, IntField

class CVSSMetrics(EmbeddedDocument):
    baseScore = FloatField()
    attackVector = StringField()
    attackComplexity = StringField()
    # ... other fields ...

class VulnerabilityImpact(EmbeddedDocument):
    impact_score = StringField(required=True)
    severity = StringField()

class VulnerableProduct(EmbeddedDocument):
    vendor = StringField(required=True)
    product = StringField(required=True)
    # Remove vulnerability_impact from here

class Vulnerability(Document):
    cve_id = StringField(primary_key=True)
    description = StringField(required=True)
    cpe_configurations = ListField(StringField())
    vulnerable_products = ListField(EmbeddedDocumentField(VulnerableProduct))
    cwes = ListField(StringField())
    attack_vector = StringField(required=True)
    known_exploit = BooleanField(default=False)
    publishedDate = DateTimeField()
    cisa_exploitability_metric = StringField()
    cvss_metrics = EmbeddedDocumentField(CVSSMetrics)
    vulnerability_impact = EmbeddedDocumentField(VulnerabilityImpact)  # Correct placement

    meta = {
        'collection': 'vulnerabilities'
    }

# Define the CVEVulnerability Document
class CVEVulnerability(Document):
    _id = StringField(primary_key=True)
    title = StringField()
    publishedDate = DateTimeField()
    catalogVersion = StringField()
    dateReleased = DateTimeField()
    count = IntField()
    vulnerabilities = ListField(EmbeddedDocumentField(VulnerableProduct))
    source = StringField()  # Indicates the data source (e.g., 'NVD', 'CISA')

    meta = {
        'collection': 'cve_vulnerabilities'
    }
from django.db import models

class CisaVulnerability(models.Model):
    cve_id = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    cvss_score = models.FloatField()
    # Add more fields as needed

    def __str__(self):
        return self.cve_id
# Query Functions
def get_vulnerabilities_for_product(product_name):
    product_name_regex = re.compile(re.escape(product_name), re.IGNORECASE)
    vulnerabilities = Vulnerability.objects(vulnerable_products__product=product_name_regex)
    vulnerability_count = vulnerabilities.count()
    print(f"There are {vulnerability_count} vulnerabilities for {product_name} (case-insensitive search).")

    # Debugging: Print out a few CVE IDs and descriptions
    for vuln in vulnerabilities[:5]:
        print(f"CVE ID: {vuln.cve_id}, Description: {vuln.description}")
def get_attack_vector_count(attack_vector):
    attack_vector_count = Vulnerability.objects(cvss_metrics__attackVector=attack_vector).count()
    print(f"There are {attack_vector_count} vulnerabilities with the attack vector {attack_vector}.")

def get_most_common_weakness_last_year():
    last_year = datetime.now().year - 1
    start_last_year = datetime(last_year, 1, 1)
    end_last_year = datetime(last_year, 12, 31)

    pipeline = [
        {"$match": {"publishedDate": {"$gte": start_last_year, "$lte": end_last_year}}},
        {"$unwind": "$cwes"},
        {"$group": {
            "_id": "$cwes",
            "count": {"$sum": 1}
        }},
        {"$sort": {"count": -1}},
        {"$limit": 1}
    ]

    results = list(Vulnerability.objects().aggregate(*pipeline))
    if results:
        most_common_weakness = results[0]
        print(f"The most common weakness is '{most_common_weakness['_id']}' with {most_common_weakness['count']} occurrences.")
    else:
        print("No weaknesses found.")

def get_top_vendor_with_known_exploits_last_year():
    last_year = datetime.now().year - 1
    start_last_year = datetime(last_year, 1, 1)
    end_last_year = datetime(last_year, 12, 31)
    pipeline = [
        {"$unwind": "$vulnerable_products"},
        {"$match": {
            "known_exploit": True,
            "publishedDate": {"$gte": start_last_year, "$lte": end_last_year}
            }},
        {"$group": {
            "_id": {
                "vendor": "$vulnerable_products.vendor",
                "product": "$vulnerable_products.product"
            },
            "count": {"$sum": 1}
        }},
        {"$sort": {"count": -1}},
        {"$limit": 1}
    ]
    results = list(Vulnerability.objects().aggregate(*pipeline))
    for i, result in enumerate(results):
        print(
            f"{i + 1}: {result['_id']['vendor']} {result['_id']['product']} has {result['count']} known exploits")
