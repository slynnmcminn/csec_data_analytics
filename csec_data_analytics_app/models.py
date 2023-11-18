from mongoengine import EmbeddedDocumentListField, BooleanField, Document, EmbeddedDocument, StringField, DateTimeField, ListField, EmbeddedDocumentField, IntField

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
    cisa_exploitability_metric = StringField()  # Adjust the field type based on actual data
