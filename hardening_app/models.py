from django.db import models
from django.contrib.auth.models import User

class HardeningRule(models.Model):
    id = models.CharField(max_length=100, primary_key=True)
    platform = models.CharField(max_length=20)  # 'windows' or 'linux'
    title = models.CharField(max_length=200)
    category = models.CharField(max_length=100)
    severity = models.CharField(max_length=20)  # 'critical', 'high', 'medium', 'low'
    description = models.TextField()
    rationale = models.TextField()
    verification = models.TextField()
    remediation = models.TextField()
    script_code = models.TextField()

    def __str__(self):
        return f"[{self.platform.upper()}] {self.title}"

class UserProgress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='progress')
    rule = models.ForeignKey(HardeningRule, on_delete=models.CASCADE)
    is_completed = models.BooleanField(default=False)
    is_included_in_script = models.BooleanField(default=True)

    class Meta:
        unique_together = ('user', 'rule')

    def __str__(self):
        return f"Progress for {self.user.username} - {self.rule_id} (Completed: {self.is_completed}, Included: {self.is_included_in_script})"

class ScanReport(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scan_reports', null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    platform = models.CharField(max_length=20)  # 'windows' or 'linux'
    score = models.FloatField()  # compliance percentage (0 to 100)
    passed_checks = models.TextField()  # JSON-encoded array or comma-separated rule IDs
    failed_checks = models.TextField()  # JSON-encoded array or comma-separated rule IDs
    device_id = models.CharField(max_length=255, default='', blank=True)

    def __str__(self):
        return f"Scan Report [{self.platform.upper()}] - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} (Score: {self.score}%) - User: {self.user.username if self.user else 'Anonymous'}"
