from mongoengine import Document, EmbeddedDocument, StringField, ListField, EmbeddedDocumentField, BooleanField, DateTimeField

class VulnerableProduct(EmbeddedDocument):
    vendor = StringField(required=True, null=False)
    product = StringField(required=True, null=False)
    cveID = StringField()
    vendorProject = StringField()
    vulnerabilityName = StringField()
    dateAdded = DateTimeField()
    shortDescription = StringField()
    requiredAction = StringField()
    dueDate = DateTimeField()
    knownRansomwareCampaignUse = StringField()
    notes = StringField()
    cvss_vector = StringField()  # Added for attack vector information
    cwe = StringField()          # Added for weakness (CWE) information

class VulnerabilityImpact(EmbeddedDocument):
    impacts = ListField(null=True)
    validated = BooleanField(default=False)

class Vulnerability(Document):
    cve_id = StringField(required=True, null=False)
    description = StringField(required=True, null=False)
    attack_vector = StringField(required=True, null=False)
    known_exploit = BooleanField(required=True, null=False)
    vulnerable_products = ListField(EmbeddedDocumentField(VulnerableProduct), required=True, null=False)
    vulnerability_impact = EmbeddedDocumentField(VulnerabilityImpact, required=False, null=True)
