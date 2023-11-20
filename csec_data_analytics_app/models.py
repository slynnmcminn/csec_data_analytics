from mongoengine import Document, EmbeddedDocument, StringField, ListField, EmbeddedDocumentField, BooleanField

class VulnerableProduct(EmbeddedDocument):
    vendor = StringField(required=True)
    product = StringField(required=True)

class Vulnerability(Document):
    cve_id = StringField(required=True, unique=True)
    description = StringField(required=True)
    attack_vector = StringField(required=True)
    known_exploit = BooleanField(default=False)
    vulnerable_products = ListField(EmbeddedDocumentField(VulnerableProduct))
    cwes = ListField(StringField())  # Field for CWE data
    cisa_exploitability_metric = StringField()

    meta = {'collection': 'vulnerabilities'}
