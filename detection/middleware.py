from .models import BlockedIP
from django.shortcuts import redirect


class BlockIPMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        ip = request.META.get("REMOTE_ADDR")

        # allow admin and unblock pages
        if (
            request.path.startswith("/admin") or
            request.path.startswith("/access-denied") or
            request.path.startswith("/unblock-ip")
        ):
            return self.get_response(request)

        if BlockedIP.objects.filter(ip_address=ip, is_active=True).exists():
            return redirect("access_denied")

        return self.get_response(request)