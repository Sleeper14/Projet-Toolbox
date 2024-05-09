from django import forms
from django.forms import ModelForm

from .models import Report


class IpscanForm(ModelForm):
    class Meta:
        model = Report
        fields = ["ip"]



class IpCommandForm(forms.Form):
    target = forms.GenericIPAddressField()
    command = forms.CharField(max_length=150)


class URLForm(forms.Form):
    target_url = forms.CharField()


class SubDomainForm(forms.Form):
    target_url = forms.CharField()
    fast_scan = forms.BooleanField(required=False)
