# -*- coding:utf-8 -*-
from __future__ import unicode_literals
from django.utils import timezone
from django.db import models

class TestModel(models.Model):
    name = models.CharField('Name' , max_length = 255)
    created = models.DateTimeField(default=timezone.now)

    def __unicode__(self):
        return self.name
