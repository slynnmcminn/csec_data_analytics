import django.db
from mongoengine import Document, EmbeddedDocument, EmbeddedDocumentListField, StringField, URLField, DictField, DecimalField, DateTimeField, ListField, EmbeddedDocumentField


class Vulnerability(django.db.models.Model):
    title = django.db.models.CharField(max_length=100)
    description = django.db.models.TextField()
    severity = django.db.models.CharField(max_length=20)
    published_date = django.db.models.DateTimeField()
    last_modified_date = django.db.models.DateTimeField()
    evaluator_comment = django.db.models.TextField()
    evaluator_solution = django.db.models.TextField()
    evaluator_impact = django.db.models.TextField()
    cisa_exploit_add_date = django.db.models.DateField()
    cisa_action_due_date = django.db.models.DateField()
    cisa_required_action = django.db.models.TextField()
    cisa_vulnerability_name = django.db.models.CharField(max_length=100)

    # Add more fields as needed for your vulnerability objects
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

    def __str__(self):
        return self.title
