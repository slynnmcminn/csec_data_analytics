from mongoengine import EmailField, IntField, BooleanField, FloatField, Document, EmbeddedDocument, EmbeddedDocumentListField, StringField, URLField, DictField, DecimalField, DateTimeField, ListField, EmbeddedDocumentField

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

class Weakness(EmbeddedDocument):
   type = StringField()  # This field represents the type of weakness

class DescriptionData(EmbeddedDocument):
   lang = StringField()
   value = StringField()

class Description(EmbeddedDocument):
   description_data = EmbeddedDocumentListField(DescriptionData)

class ReferenceData(EmbeddedDocument):
   url = URLField()
   name = StringField()
   resource = StringField()
   tags = ListField(StringField())

class ProblemTypeData(EmbeddedDocument):
   description = EmbeddedDocumentListField(DescriptionData)

class CVEDataMeta(EmbeddedDocument):
   ID = StringField()
   ASSIGNER = StringField()

class CVEData(EmbeddedDocument):
   data_type = StringField()
   data_format = StringField()
   data_version = StringField()
   CVE_data_meta = EmbeddedDocumentField(CVEDataMeta)
   references = DictField()
   description = EmbeddedDocumentField(DescriptionData)

class BaseMetricV3(EmbeddedDocument):
   cvssV3 = DictField()
   exploitabilityScore = DecimalField()
   impactScore = DecimalField()

class Impact(EmbeddedDocument):
   baseMetricV3 = EmbeddedDocumentField(BaseMetricV3)

class Configuration(EmbeddedDocument):
   CVE_data_version = StringField()
   nodes = ListField(DictField())

class Vulnerability(Document):
   cve_id = StringField(required=True, null=False)
   description = StringField(required=True, null=False)
   attack_vector = StringField(required=True, null=False)
   known_exploit = BooleanField(required=True, null=False)
   vulnerable_products = EmbeddedDocumentListField(VulnerableProduct, required=True, null=False)
   vulnerability_impact = EmbeddedDocumentField(VulnerabilityImpact, required=False, null=True)
   weakness = EmbeddedDocumentField(Weakness)  # Embed the Weakness document in Vulnerability
   date_added = DateTimeField()
   cvss_score = FloatField()
   vendor = StringField(required=True)
   product = StringField(required=True)
   cve = EmbeddedDocumentField(CVEData)
   configurations = EmbeddedDocumentField(Configuration)
   cvssV3 = DictField()
   exploitabilityScore = DecimalField()
   impactScore = DecimalField()
   impact = EmbeddedDocumentField(Impact)
   publishedDate = DateTimeField()
   lastModifiedDate = DateTimeField()

