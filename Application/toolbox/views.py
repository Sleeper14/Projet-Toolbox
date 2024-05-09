import multiprocessing
import os
import re

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.http.response import Http404, HttpResponse, StreamingHttpResponse
from django.shortcuts import redirect, render
from django.http import HttpResponseBadRequest

from .forms import (
    IpCommandForm,
    IpscanForm,
    SubDomainForm,
    URLForm,
)
from .scripts import dirscanner, nmap, rustscan
from .scripts.webapp import (
    cve_2021_41773,
    cve_2022_1388,
    gather_url,
    subdomain_finder,
    verbtampering,
)
from .scripts.windows import rdpbrute

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def home(request):
    return render(request, "home.html")


def loginuser(request):
    if request.method == "GET":
        if request.user.is_authenticated:
            return render(request, "dashboard.html")
        else:
            return render(request, "login.html", {"form": AuthenticationForm()})

    else:
        user = authenticate(
            request,
            username=request.POST["username"],
            password=request.POST["password"],
        )
        if user is None:
            return render(
                request,
                "login.html",
                {"form": AuthenticationForm(), "error": "Nom d'utilisateur/mot de passe incorrect"},
            )
        else:
            login(request, user)
            return redirect("dashboard")


@login_required(login_url="/forbidden/")
def dashboard(request):
    if request.method == "GET":
        return render(request, "dashboard.html")


@login_required(login_url="/forbidden/")
def scan_hote(request):
    if request.method == "GET":
        return render(request, "scan_hote.html", {"form": IpscanForm()})

    else:
        try:
            global ip, user_name, function_name
            form = IpscanForm(request.POST)
            if form.is_valid():
                ip = form.cleaned_data.get("ip")
                function_name = "scan_hote"
                user_name = request.user
                p_scan_hote = multiprocessing.Process(
                    target=nmap.nmap_script,
                    args=(
                        ip,
                        user_name,
                        function_name,
                    ),
                )
                p_scan_hote.start()
                p_scan_hote.join()

        except ValueError:
            return render(
                request,
                "dashboard.html",
                {"error": "Bad data passed in. Try again."},
            )

    return render(request, "download.html")


@login_required(login_url="/forbidden/")
def scan_reseau(request):
    if request.method == "GET":
        return render(request, "scan_reseau.html", {"form": IpscanForm()})

    else:
        try:
            global ip, user_name, function_name
            form = IpscanForm(request.POST)
            if form.is_valid():
                ip = form.cleaned_data.get("ip")
            function_name = scan_reseau.__name__
            user_name = request.user
            p_scan_reseau = multiprocessing.Process(
                target=rustscan.rustscan_script,
                args=(
                    ip,
                    user_name,
                    function_name,
                ),
            )
            p_scan_reseau.start()
            p_scan_reseau.join()
            ip = str(ip).split("/")[0]

        except ValueError:
            return render(
                request,
                "dashboard.html",
                {"form": IpscanForm()},
                {"error": "Bad data passed in. Try again."},
            )

    return render(request, "download.html")


@login_required(login_url="/forbidden/")
def dirscan(request):
    if request.method == "GET":
        return render(request, "dirscan.html", {"form": IpscanForm()})

    elif request.method == "POST":
        try:
            global ip, user_name, function_name
            form = IpscanForm(request.POST)
            if form.is_valid():
                ip = form.cleaned_data.get("ip")
            function_name = dirscan.__name__
            user_name = request.user
            response = StreamingHttpResponse(
                dirscanner.dirscan_script(ip, user_name, function_name)
            )
            response["Content-Type"] = "text/event-stream"
            return response

        except ValueError:
            return render(
                request,
                "dashboard.html",
                {"form": IpscanForm()},
                {"error": "Bad data passed in. Try again."},
            )

    return render(request, "download.html")


@login_required(login_url="/forbidden/")
def stream(request):
    response = StreamingHttpResponse()
    response["Content-Type"] = "text/event-stream"
    return response


@login_required(login_url="/forbidden/")
def linux(request):
    return render(request, "linux/home.html")



@login_required(login_url="/forbidden/")
def rdpbruteforce(request):
    if request.method == "GET":
        return render(
            request, "windows/rdpbruteforce.html", {"form": IpscanForm()}
        )

    else:
        form = IpscanForm(request.POST)
        if form.is_valid():
            ip = form.cleaned_data.get("ip")
            response = StreamingHttpResponse(
                rdpbrute.rdpbrute_script(ip)
            )  # Accept generator/yield
            response["Content-Type"] = "text/event-stream"
            return response

        return render(
            request,
            "windows/rdpbruteforce.html",
            {"error": "Bad data passed in. Try again."},
        )


@login_required(login_url="/forbidden/")
def nightmare(request):
    return render(request, "scan_hote.html")



@login_required(login_url="/forbidden/")
def verbtamper(request):
    if request.method == "GET":
        return render(request, "webapp/verbtampering.html", {"form": URLForm()})

    else:
        try:
            global target_url, user_name
            form = URLForm(request.POST)
            if form.is_valid():
                target_url = form.cleaned_data.get("target_url")
                user_name = request.user
                result = verbtampering.start(target_url, user_name)
                if result is None:
                    return render(
                        request,
                        "webapp/verbtampering.html",
                        {"error": "Bad URL Passed in, Try again..."},
                    )
                else:
                    context = {"result": result.items(), "target_url": target_url}
                    return render(request, "webapp/verbtampering.html", context)

        except ValueError:
            return render(
                request,
                "webapp/verbtampering.html",
                {"error": "Bad data passed in. Try again."},
            )


@login_required(login_url="/forbidden/")
def webcrawler(request):
    if request.method == "GET":
        return render(request, "webapp/webcrawler.html", {"form": URLForm()})

    else:
        try:
            global target_url
            form = URLForm(request.POST)
            if form.is_valid():
                target_url = form.cleaned_data.get("target_url")
                result = gather_url.get(target_url)
                if result is None:
                    return render(
                        request,
                        "webapp/webcrawler.html",
                        {"error": "Bad URL Passed in, Try again..."},
                    )

                else:
                    context = {"result": result, "target_url": target_url}
                    return render(request, "webapp/webcrawler.html", context)

        except ValueError:
            return render(
                request,
                "webapp/webcrawler.html",
                {"error": "Données incorrectes fournies. Veuillez réessayer."},
            )


@login_required(login_url="/forbidden/")
def subdomain(request):
    if request.method == "GET":
        return render(request, "webapp/subdomain.html", {"form": SubDomainForm()})

    form = SubDomainForm(request.POST)
    if not form.is_valid():
        return HttpResponseBadRequest("Invalid form data.")

    target_url = form.cleaned_data.get("target_url")
    target_url = re.search(
        r"\w+\.\w+",
        target_url.replace("https://", "").replace("http://", "").replace("www.", ""),
    )[0]

    if target_url is None:
        return render(
            request,
            "webapp/subdomain.html",
            {"error": "Bad URL Passed in, Try again..."},
        )
    result = subdomain_finder.sublister(target_url)
    if result is None:
        return render(
            request,
            "webapp/subdomain.html",
            {"error": "Bad URL Passed in, Try again..."},
        )

    context = {"result": result, "target_url": target_url}
    return render(request, "webapp/subdomain.html", context)



@login_required(login_url="/forbidden/")
def apache_cve_41773(request):
    if request.method == "GET":
        return render(
            request, "webapp/cve_2021_41773.html", {"form": IpscanForm()}
        )

    else:
        form = IpscanForm(request.POST)
        if form.is_valid():
            ip = form.cleaned_data.get("ip")
            result = cve_2021_41773.start(ip)
            if result is not None:
                context = {"result": result}
                return render(request, "webapp/cve_2021_41773.html", context)

            else:
                return render(
                    request,
                    "webapp/cve_2021_41773.html",
                    {"error": "Something went wrong..."},
                )

        return render(
            request,
            "webapp/cve_2021_41773.html",
            {"error": "Bad data passed in. Try again."},
        )


@login_required(login_url="/forbidden/")
def f5_bigip_cve_1388(request):
    if request.method == "GET":
        return render(
            request, "webapp/cve_2022_1388.html", {"form": IpCommandForm()}
        )

    else:
        form = IpCommandForm(request.POST)
        if form.is_valid():
            target = form.cleaned_data.get("target")
            command = form.cleaned_data.get("command")
            result = cve_2022_1388.exploit(target, command)
            if result is not None:
                context = {"result": result}
                return render(request, "webapp/cve_2022_1388.html", context)

            else:
                return render(
                    request,
                    "webapp/cve_2022_1388.html",
                    {"error": "Something went wrong..."},
                )

        return render(
            request,
            "webapp/cve_2022_1388.html",
            {"error": "Bad data passed in. Try again."},
        )




@login_required(login_url="/forbidden/")
def download_file(request):
    filename = f"{function_name}-{ip}.pdf"
    user_name = request.user
    filepath = f"{BASE_DIR}/toolbox/media/reports/{user_name}/{filename}"
    if os.path.exists(filepath):
        response = HttpResponse(open(filepath, "rb"))
        response["Content-Disposition"] = "attachment; filename=%s" % filename
        return response
    # Return the response value
    else:
        raise Http404


@login_required(login_url="/forbidden/")
def logoutuser(request):
    if request.method == "POST":
        logout(request)
        return redirect("home")

    else:
        return render(request, "home.html")


def forbidden(request):
    if request.method == "GET":
        return render(request, "403.html")
