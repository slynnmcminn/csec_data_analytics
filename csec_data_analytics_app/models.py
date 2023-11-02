from mongoengine import Document, StringField, EmailField, EmbeddedDocument, IntField, EmbeddedDocumentField, \
    EmbeddedDocumentListField, BooleanField, DateTimeField

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

