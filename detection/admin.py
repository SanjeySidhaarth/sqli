from django.contrib import admin
from .models import DetectionLog, BlockedIP, SecurityProfile


# -----------------------------
# Detection Logs Admin
# -----------------------------
@admin.register(DetectionLog)
class DetectionLogAdmin(admin.ModelAdmin):

    list_display = (
        "user",
        "ip_address",
        "prediction",
        "risk_level",
        "created_at"
    )

    list_filter = (
        "prediction",
        "risk_level",
        "created_at"
    )

    search_fields = (
        "user__username",
        "ip_address",
        "input_query"
    )

    ordering = ("-created_at",)

    readonly_fields = ("created_at",)


# -----------------------------
# Blocked IP Admin
# -----------------------------
@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):

    list_display = (
        "ip_address",
        "reason",
        "is_active",
        "blocked_at"
    )

    list_filter = (
        "is_active",
        "blocked_at"
    )

    search_fields = (
        "ip_address",
        "reason"
    )

    ordering = ("-blocked_at",)

    actions = ["activate_ip", "deactivate_ip"]


    def activate_ip(self, request, queryset):
        queryset.update(is_active=True)

    activate_ip.short_description = "Block selected IPs"


    def deactivate_ip(self, request, queryset):
        queryset.update(is_active=False)

    deactivate_ip.short_description = "Unblock selected IPs"


# -----------------------------
# Security Profile Admin
# -----------------------------
@admin.register(SecurityProfile)
class SecurityProfileAdmin(admin.ModelAdmin):

    list_display = (
        "user",
        "malicious_attempts",
        "is_verified"
    )

    search_fields = (
        "user__username",
    )