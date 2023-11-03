from mongoengine import Document, StringField, EmailField, EmbeddedDocument, IntField, EmbeddedDocumentField, \
    EmbeddedDocumentListField, BooleanField, DateTimeField


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


class Vulnerability(Document):
    cve_id = StringField(required=True, null=False)
    description = StringField(required=True, null=False)
    attack_vector = StringField(required=True, null=False)
    known_exploit = BooleanField(required=True, null=False)
    vulnerable_products = EmbeddedDocumentListField(VulnerableProduct, required=True, null=False)

class CVEVulnerability(Document):
   cve_id = StringField(required=True, unique=True)
   description = StringField(required=True)
   published_date = DateTimeField()
   severity = StringField()
   attack_vector = StringField()
   impact_score = StringField()
   references = StringField()
   cvss_vector = StringField()
   affected_vendors = StringField()
   affected_products = StringField()
   nested_data = StringField()
