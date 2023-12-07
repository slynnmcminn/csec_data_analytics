from mongoengine import Document, StringField, EmailField, EmbeddedDocument, IntField, EmbeddedDocumentField, \
    Document, ListField, ReferenceField, EmbeddedDocumentListField, BooleanField, ListField, DateTimeField, FloatField

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


class VulnerableProduct(Document):
    vendor = StringField(required=True)
    product = StringField(required=True)

class VulnerabilityImpact(EmbeddedDocument):
    impacts = ListField(null=True)
    validated = BooleanField(default=False)
    vendor = StringField(required=True)
    product = StringField(required=True)

class Weakness(EmbeddedDocument):
    type = StringField()  # This field represents the type of weakness

class Vulnerability(Document):
    cve_id = StringField(required=True, null=False)
    description = StringField(required=True, null=False)
    attack_vector = StringField(required=True, null=False)
    known_exploit = BooleanField(required=True, null=False)
    vulnerable_products = ListField(ReferenceField(VulnerableProduct), required=False)
    cvss_score = FloatField()
    vulnerability_impact = EmbeddedDocumentField(VulnerabilityImpact, required=False, null=True)
    weakness = EmbeddedDocumentField(Weakness)  # Embed the Weakness document in Vulnerability
    date_added = DateTimeField()

