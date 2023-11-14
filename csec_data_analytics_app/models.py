from mongoengine import Document, EmbeddedDocument, StringField, DateTimeField, ListField, EmbeddedDocumentField, IntField, FloatField

class VulnerabilityItem(EmbeddedDocument):
    cveID = StringField()
    vendorProject = StringField()
    product = StringField()
    vulnerabilityName = StringField()
    dateAdded = DateTimeField()
    shortDescription = StringField()
    requiredAction = StringField()
    dueDate = DateTimeField()
    knownRansomwareCampaignUse = StringField()
    notes = StringField()
    cvss_vector = StringField()  # Added for attack vector information
    cwe = StringField()          # Added for weakness (CWE) information

class CVEVulnerability(Document):
    _id = StringField(primary_key=True)  # Assuming you want to use this as your primary key
    title = StringField()
    catalogVersion = StringField()
    dateReleased = DateTimeField()
    count = IntField()
    vulnerabilities = ListField(EmbeddedDocumentField(VulnerabilityItem))

    class Meta:
        db_table = 'c_v_e_vulnerability'  # Specify the collection name