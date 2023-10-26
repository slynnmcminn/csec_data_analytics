from django.db import models


class Vulnerability(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    severity = models.CharField(max_length=20)
    published_date = models.DateTimeField()
    last_modified_date = models.DateTimeField()
    evaluator_comment = models.TextField()
    evaluator_solution = models.TextField()
    evaluator_impact = models.TextField()
    cisa_exploit_add_date = models.DateField()
    cisa_action_due_date = models.DateField()
    cisa_required_action = models.TextField()
    cisa_vulnerability_name = models.CharField(max_length=100)

    # Add more fields as needed for your vulnerability objects

    def __str__(self):
        return self.title
