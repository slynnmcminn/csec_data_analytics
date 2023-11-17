from mongoengine import Document, EmbeddedDocument, StringField, DateTimeField, ListField, EmbeddedDocumentField, IntField

class VulnerabilityItem(EmbeddedDocument):
    cveID = StringField(required=True)
    description = StringField()
    vendorProject = StringField()
    product = StringField()
    vulnerabilityName = StringField()
    dateAdded = DateTimeField()
    shortDescription = StringField()
    requiredAction = StringField()
    dueDate = DateTimeField()
    knownRansomwareCampaignUse = StringField()
    notes = StringField()
    cvss_vector = StringField()  # For attack vector information
    cwe = StringField()          # For weakness (CWE) information
    # Add any additional fields that are unique to CISA or NVD data

class CVEVulnerability(Document):
    _id = StringField(primary_key=True)
    title = StringField()
    publishedDate = DateTimeField()
    catalogVersion = StringField()
    dateReleased = DateTimeField()
    count = IntField()
    vulnerabilities = ListField(EmbeddedDocumentField(VulnerabilityItem))
    source = StringField()  # New field to indicate the data source (e.g., 'NVD', 'CISA')

    meta = {'collection': 'cve_vulnerabilities'}
