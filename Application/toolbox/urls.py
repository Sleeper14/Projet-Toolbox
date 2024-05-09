from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("login/", views.loginuser, name="loginuser"),
    path("logout/", views.logoutuser, name="logoutuser"),
    path("forbidden/", views.forbidden, name="forbidden"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("scan_hote/", views.scan_hote, name="scan_hote"),
    path("scan_reseau/", views.scan_reseau, name="scan_reseau"),
    path("dirscan/", views.dirscan, name="dirscan"),
    path("linux/", views.linux, name="linux"),
    path("windows/nightmare/", views.nightmare, name="nightmare"),
    path("windows/rdpbruteforce/", views.rdpbruteforce, name="rdpbruteforce"),
    path("download/", views.download_file, name="download_file"),
    path("stream/", views.stream, name="stream"),
    path("webapp/verbtampering", views.verbtamper, name="verbtamper"),
    path("webapp/webcrawler", views.webcrawler, name="webcrawler"),
    path("webapp/subdomain", views.subdomain, name="subdomain"),
    path(
        "webapp/apache-cve-21-41773", views.apache_cve_41773, name="apache_cve_21_41773"
    ),
    path(
        "webapp/f5-bigip-cve-22-1388", views.f5_bigip_cve_1388, name="f5_bigip_22_1388"
    ),
    # <str:filepath>/
]
