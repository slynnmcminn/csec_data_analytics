from mongoengine import (DateTimeField, Document, EmbeddedDocument,
                         EmbeddedDocumentField, FloatField, ListField,
                         StringField)


class CVSSAttributes(EmbeddedDocument):
    base_score = FloatField()
    exploitability_score = FloatField()
    impact_score = FloatField()
    access_vector = StringField()
    access_complexity = StringField()
    authentication = StringField()
    confidentiality_impact = StringField()
    integrity_impact = StringField()
    availability_impact = StringField()

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
    cpe_configurations = ListField(StringField())
    cwes = ListField(StringField())
    cisa_exploitability_metric = StringField()
    cvss_attributes = EmbeddedDocumentField(CVSSAttributes)
