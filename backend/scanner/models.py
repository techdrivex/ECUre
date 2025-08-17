"""
Scanner models for ECU firmware analysis.
"""

import os
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import FileExtensionValidator


class ECUDevice(models.Model):
    """ECU device information."""
    
    DEVICE_TYPES = [
        ('ENGINE', 'Engine Control Unit'),
        ('TRANSMISSION', 'Transmission Control Unit'),
        ('BRAKE', 'Brake Control Unit'),
        ('STEERING', 'Steering Control Unit'),
        ('BODY', 'Body Control Module'),
        ('INFOTAINMENT', 'Infotainment System'),
        ('OTHER', 'Other'),
    ]
    
    name = models.CharField(max_length=200)
    device_type = models.CharField(max_length=20, choices=DEVICE_TYPES)
    manufacturer = models.CharField(max_length=200)
    model = models.CharField(max_length=200)
    version = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'ECU Device'
        verbose_name_plural = 'ECU Devices'
        unique_together = ['manufacturer', 'model', 'version']
    
    def __str__(self):
        return f"{self.manufacturer} {self.model} {self.version}"


class FirmwareFile(models.Model):
    """ECU firmware file upload."""
    
    STATUS_CHOICES = [
        ('UPLOADED', 'Uploaded'),
        ('PROCESSING', 'Processing'),
        ('ANALYZED', 'Analyzed'),
        ('FAILED', 'Failed'),
    ]
    
    file = models.FileField(
        upload_to='firmware/',
        validators=[FileExtensionValidator(allowed_extensions=['bin', 'hex', 'elf', 's19', 'mot'])]
    )
    original_filename = models.CharField(max_length=255)
    file_size = models.BigIntegerField()
    file_hash = models.CharField(max_length=64)  # SHA-256
    ecu_device = models.ForeignKey(ECUDevice, on_delete=models.CASCADE, null=True, blank=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='UPLOADED')
    upload_date = models.DateTimeField(auto_now_add=True)
    analysis_date = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = 'Firmware File'
        verbose_name_plural = 'Firmware Files'
    
    def __str__(self):
        return f"{self.original_filename} ({self.status})"
    
    def save(self, *args, **kwargs):
        if not self.file_size:
            self.file_size = self.file.size
        super().save(*args, **kwargs)


class ScanSession(models.Model):
    """ECU firmware scanning session."""
    
    SCAN_TYPES = [
        ('STATIC', 'Static Analysis'),
        ('DYNAMIC', 'Dynamic Analysis'),
        ('FULL', 'Full Analysis'),
    ]
    
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('RUNNING', 'Running'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('CANCELLED', 'Cancelled'),
    ]
    
    firmware_file = models.ForeignKey(FirmwareFile, on_delete=models.CASCADE)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    initiated_by = models.ForeignKey(User, on_delete=models.CASCADE)
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    progress = models.IntegerField(default=0)  # 0-100
    scan_config = models.JSONField(default=dict)
    results_summary = models.JSONField(default=dict, blank=True)
    
    class Meta:
        verbose_name = 'Scan Session'
        verbose_name_plural = 'Scan Sessions'
        ordering = ['-start_time']
    
    def __str__(self):
        return f"Scan {self.id} - {self.firmware_file.original_filename} ({self.status})"


class Vulnerability(models.Model):
    """Vulnerability findings from scans."""
    
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
        ('INFO', 'Informational'),
    ]
    
    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('IN_PROGRESS', 'In Progress'),
        ('RESOLVED', 'Resolved'),
        ('FALSE_POSITIVE', 'False Positive'),
    ]
    
    scan_session = models.ForeignKey(ScanSession, on_delete=models.CASCADE)
    title = models.CharField(max_length=500)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN')
    cve_id = models.CharField(max_length=20, blank=True)
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    location = models.JSONField(default=dict)  # File, line, function, etc.
    evidence = models.TextField(blank=True)
    recommendations = models.TextField(blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        verbose_name = 'Vulnerability'
        verbose_name_plural = 'Vulnerabilities'
        ordering = ['-severity', '-discovered_at']
    
    def __str__(self):
        return f"{self.title} ({self.severity})"


class ScanResult(models.Model):
    """Detailed scan results and metadata."""
    
    scan_session = models.ForeignKey(ScanSession, on_delete=models.CASCADE)
    result_type = models.CharField(max_length=100)  # e.g., 'string_analysis', 'function_analysis'
    result_data = models.JSONField()
    confidence_score = models.DecimalField(max_digits=3, decimal_places=2, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'Scan Result'
        verbose_name_plural = 'Scan Results'
    
    def __str__(self):
        return f"{self.result_type} for Scan {self.scan_session.id}"
