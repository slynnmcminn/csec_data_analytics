from mongoengine import EmbeddedDocumentListField, BooleanField, Document, EmbeddedDocument, StringField, DateTimeField, ListField, EmbeddedDocumentField, IntField

class VulnerabilityItem(EmbeddedDocument):
    cveID = StringField(required=True)
    description = StringField()
    vendorProject = StringField()
    product = StringField()
    vulnerabilityName = StringField()
    dateAdded = DateTimeField()
    shortDescription = StringField()
    requiredAction = StringField()
    dueDate = DateTimeField()
    knownRansomwareCampaignUse = StringField()
    notes = StringField()
    cvss_vector = StringField()  # For attack vector information
    cwe = StringField()          # For weakness (CWE) information
    # Add any additional fields that are unique to CISA or NVD data

class CVEVulnerability(Document):
    _id = StringField(primary_key=True)
    title = StringField()
    publishedDate = DateTimeField()
    catalogVersion = StringField()
    dateReleased = DateTimeField()
    count = IntField()
    vulnerabilities = ListField(EmbeddedDocumentField(VulnerabilityItem))
    source = StringField()  # New field to indicate the data source (e.g., 'NVD', 'CISA')

    meta = {'collection': 'cve_vulnerabilities'}

class VulnerableProduct(EmbeddedDocument):
    vendor = StringField(required=True, null=False)
    product = StringField(required=True, null=False)

class VulnerabilityImpact(EmbeddedDocument):
    impacts = ListField(null=True)
    validated = BooleanField(default=False)

class Vulnerability(Document):
    cve_id = StringField(required=True, null=False)
    description = StringField(required=True, null=False)
    attack_vector = StringField(required=True, null=False)
    known_exploit = BooleanField(required=True, null=False)
    vulnerable_products = EmbeddedDocumentListField(VulnerableProduct, required=True, null=False)
    vulnerability_impact = EmbeddedDocumentField(VulnerabilityImpact, required=False, null=True)