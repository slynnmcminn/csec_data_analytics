from mongoengine import Document, EmbeddedDocument, StringField, DateTimeField, ListField, EmbeddedDocumentField, BooleanField

class VulnerableProduct(EmbeddedDocument):
    vendor = StringField(required=True)
    product = StringField(required=True)

class VulnerabilityImpact(EmbeddedDocument):
    impacts = ListField(StringField())
    validated = BooleanField(default=False)

class Vulnerability(Document):
    cve_id = StringField(required=True, unique=True)
    description = StringField(required=True)
    attack_vector = StringField(required=True)
    known_exploit = BooleanField(default=False)
    vulnerable_products = ListField(EmbeddedDocumentField(VulnerableProduct))
    vulnerability_impact = EmbeddedDocumentField(VulnerabilityImpact)
    cisa_exploitability_metric = StringField()
    cwes = ListField(StringField())

    meta = {'collection': 'vulnerabilities'}
