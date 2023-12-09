from mongoengine import Document, StringField, EmailField, EmbeddedDocument, IntField, EmbeddedDocumentField, \
    EmbeddedDocumentListField, BooleanField, ListField


class UserAddress(EmbeddedDocument):
    street = StringField(required=True, null=False)
    city = StringField(required=True, null=False)
    state = StringField(required=True, null=False)
    country = StringField(required=True, null=False)
    zip = IntField(required=True, null=False)


class User(Document):
    # mongoengine defaults to allow null
    first_name = StringField(required=True, null=False)
    last_name = StringField(required=True, null=False)
    email = EmailField(required=True, null=False)
    address = EmbeddedDocumentField(UserAddress, required=True)


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
