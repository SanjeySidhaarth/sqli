from django.db import models
from django.contrib.auth.models import User

class SecurityProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    malicious_attempts = models.IntegerField(default=0)
    is_verified = models.BooleanField(default=True)
    verification_token = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return self.user.username

from django.db import models
from django.contrib.auth.models import User

class DetectionLog(models.Model):

    user = models.ForeignKey(User, on_delete=models.CASCADE)

    ip_address = models.GenericIPAddressField()

    input_query = models.TextField()

    prediction = models.CharField(max_length=50)

    risk_level = models.CharField(max_length=20)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.prediction}"


class BlockedIP(models.Model):

    ip_address = models.GenericIPAddressField(unique=True)

    blocked_at = models.DateTimeField(auto_now_add=True)

    reason = models.CharField(max_length=255, default="Malicious activity")

    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.ip_address