from django.shortcuts import render


def index(requset):
    return render(requset, 'index.html')


def blocked(request):
    return render(request, 'blocked.html')
