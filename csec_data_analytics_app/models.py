from mongoengine import Document, StringField, ListField, EmbeddedDocument, EmbeddedDocumentField, BooleanField, DateTimeField, IntField, FloatField

class CVSSMetrics(EmbeddedDocument):
    baseScore = FloatField()
    attackVector = StringField()
    attackComplexity = StringField()
    # Add other CVSS attributes as needed

class VulnerabilityImpact(EmbeddedDocument):
    impact_score = StringField(required=True)
    severity = StringField(required=True)

class VulnerableProduct(EmbeddedDocument):
    vendor = StringField(required=True)
    product = StringField(required=True)

class Vulnerability(Document):
    cve_id = StringField(primary_key=True)
    description = StringField(required=True)
    vulnerable_products = ListField(EmbeddedDocumentField(VulnerableProduct))
    cwes = ListField(StringField())
    attack_vector = StringField(required=True)
    known_exploit = BooleanField(default=False)
    publishedDate = DateTimeField()
    cisa_exploitability_metric = StringField()
    cvss_metrics = EmbeddedDocumentField(CVSSMetrics)

    meta = {
        'collection': 'vulnerabilities'
    }

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
