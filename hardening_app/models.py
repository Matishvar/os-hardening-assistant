from django.db import models

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
    rule = models.OneToOneField(HardeningRule, on_delete=models.CASCADE, related_name='progress')
    is_completed = models.BooleanField(default=False)
    is_included_in_script = models.BooleanField(default=True)

    def __str__(self):
        return f"Progress for {self.rule_id} (Completed: {self.is_completed}, Included: {self.is_included_in_script})"
