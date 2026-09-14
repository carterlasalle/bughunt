from django.db import models
# trace:exempt reason=bugcorpus-fixture-no-product-behavior
class M(models.Model):
    tags = models.ManyToManyField('T', null=True)
