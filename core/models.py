from django.db import models

from django.db import models
from django.contrib.auth.models import User

# Health Data
class HealthData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(auto_now_add=True)
    type = models.CharField(max_length=50)  # e.g., Exercise, Diet
    category = models.CharField(max_length=50, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    calories = models.IntegerField(blank=True, null=True)
    duration = models.IntegerField(blank=True, null=True)  # in minutes

    def __str__(self):
        return f"{self.user.username} - {self.type} on {self.date}"

# Goals
class Goal(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    goal_type = models.CharField(max_length=100)  # e.g., Weight Loss, Fitness
    target_value = models.FloatField()
    current_value = models.FloatField(default=0)
    start_date = models.DateField()
    end_date = models.DateField()

    def __str__(self):
        return f"{self.user.username} - {self.goal_type}"

# Reminders
class Reminder(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    type = models.CharField(max_length=50)
    date = models.DateField()
    time = models.TimeField()
    status = models.BooleanField(default=False)  # True if done
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.user.username} - {self.type} at {self.time}"

# Medical Records
class MedicalRecord(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    file_path = models.FileField(upload_to='medical_records/')
    record_date = models.DateField()

    def __str__(self):
        return f"{self.user.username} - {self.title}"
    
# models.py
from django.db import models
from django.contrib.auth.models import User

class HealthRecord(models.Model):
    """
    Model for storing user health records
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='health_records')
    date = models.DateField()
    
    # Health metrics
    weight = models.FloatField(null=True, blank=True, help_text="Weight in kilograms")
    calories = models.IntegerField(null=True, blank=True, help_text="Daily calorie intake")
    steps = models.IntegerField(null=True, blank=True, help_text="Daily step count")
    sleep_hours = models.FloatField(null=True, blank=True, help_text="Hours of sleep")
    water_intake = models.IntegerField(null=True, blank=True, help_text="Water intake in milliliters")
    
    # Additional metrics
    blood_pressure_systolic = models.IntegerField(null=True, blank=True)
    blood_pressure_diastolic = models.IntegerField(null=True, blank=True)
    heart_rate = models.IntegerField(null=True, blank=True)
    blood_sugar = models.FloatField(null=True, blank=True)
    
    # Notes
    notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-date']
        unique_together = ['user', 'date']
    
    def __str__(self):
        return f"{self.user.username} - {self.date}"
    
    @property
    def bmi(self):
        """Calculate BMI if height is available in user profile"""
        if hasattr(self.user, 'profile') and self.user.profile.height and self.weight:
            height_m = self.user.profile.height / 100  # Convert cm to meters
            return round(self.weight / (height_m ** 2), 1)
        return None    

