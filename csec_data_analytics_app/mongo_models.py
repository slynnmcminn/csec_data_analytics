from mongoengine import FloatField, DateTimeField
from mongoengine import Document, StringField, ListField

class MEVulnerability(Document):
    cve_id = StringField(required=True, unique=True)
    description = StringField(required=True)
    cpe_configurations = ListField(StringField())
    cwes = ListField(StringField())
    cisa_exploitability_metric = StringField()
    cvss_base_score = FloatField()
    cvss_vector = StringField()
    cvss_access_vector = StringField()
    cvss_access_complexity = StringField()
    cvss_authentication = StringField()
    cvss_confidentiality_impact = StringField()
    cvss_integrity_impact = StringField()
    cvss_availability_impact = StringField()
    cvss_exploitability_score = FloatField()
    cvss_impact_score = FloatField()
    published_date = DateTimeField()
    last_modified_date = DateTimeField()
