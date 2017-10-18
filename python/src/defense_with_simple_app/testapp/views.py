# -*- coding:utf-8 -*-
from django.shortcuts import render, redirect
from forms import TestModelForm
from defense.middleware import handling_middleware

def test_form(request):
    handel = handling_middleware()

    # check if faking input
    handel.checkFakeInput(request, 'fake_input', '1')


    if request.method == 'POST':
        form = TestModelForm(request.POST)
        if form.is_valid():
            form.save()
            # using commented return to check Vulnerabiliry URL and accessing Non existing file

            # return redirect('http://localhost:8000/admin/login/?next=/admin/acunetix/x.bacKup')
            return redirect('/')
    else:
        form = TestModelForm()
    return render(request, "test_creating_form.html", {
        "form": form,
    })
