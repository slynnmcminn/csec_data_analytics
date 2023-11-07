from mongoengine import Document, StringField, DateTimeField, IntField, ListField, DictField

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

    # Additional fields from your previous model
    catalogVersion = StringField()
    title = StringField()
    count = IntField()
    vulnerabilities = ListField(DictField())
    dateReleased = StringField()
    cpe_configurations = ListField(DictField())
    cwes = ListField(StringField())
    cisa_exploitability_metric = StringField()
    cvss = DictField()
