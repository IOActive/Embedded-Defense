# -*- coding: utf-8 -*-
from django.forms import ModelForm
from testapp.models import *

class TestModelForm(ModelForm):
    class Meta:
         model = TestModel
         fields = ['name']

    def __init__(self, *args, **kwargs):
        super(TestModelForm, self).__init__(*args, **kwargs)

