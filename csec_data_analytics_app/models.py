from mongoengine import Document, StringField, EmailField, EmbeddedDocument, IntField, EmbeddedDocumentField, DateField, EmbeddedDocumentListField, BooleanField, ListField

class UserAddress(EmbeddedDocument):
    street = StringField(required=True)
    city = StringField(required=True)
    state = StringField(required=True)
    country = StringField(required=True)
    zip = IntField(required=True)

class User(Document):
    first_name = StringField(required=True)
    last_name = StringField(required=True)
    email = EmailField(required=True)
    address = EmbeddedDocumentField(UserAddress, required=True)

class VulnerableProduct(EmbeddedDocument):
    vendor = StringField(required=True)
    product = StringField(required=True)

class VulnerabilityImpact(EmbeddedDocument):
    impacts = ListField(default=list)
    validated = BooleanField(default=False)

class Vulnerability(Document):
    cve_id = StringField(required=True)
    description = StringField(required=True)
    attack_vector = StringField(required=True)
    known_exploit = BooleanField(required=True)
    vulnerable_products = EmbeddedDocumentListField(VulnerableProduct, required=True)
    vulnerability_impact = EmbeddedDocumentField(VulnerabilityImpact)

class CVEVulnerability(Document):
    cve_id = StringField(required=True)
    description = StringField(required=True)
    attack_vector = StringField(required=True)
    known_exploit = BooleanField(required=True)
    vulnerable_products = EmbeddedDocumentListField(VulnerableProduct, required=True)
    vulnerability_impact = EmbeddedDocumentField(VulnerabilityImpact)
    cpe_name = StringField()
    vendor_project = StringField(required=True)
    vulnerability_name = StringField(required=True)
    date_added = DateField()
    short_description = StringField(required=True)
    required_action = StringField(required=True)
    due_date = DateField()
    cvss_v3_metrics = StringField(required=True)
    cvss_v2_severity = StringField()
    cvss_v3_severity = StringField()
    cwe_id = StringField(required=True)
    is_vulnerable = BooleanField()
    pub_start_date = DateField(required=True)
    pub_end_date = DateField(required=True)
    known_ransomware_campaign_use = StringField()
    notes = StringField()
