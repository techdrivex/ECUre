"""
API serializers for ECUre application.
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from core.models import UserProfile
from scanner.models import ECUDevice, FirmwareFile, ScanSession, Vulnerability, ScanResult


class UserSerializer(serializers.ModelSerializer):
    """User serializer."""
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'date_joined']
        read_only_fields = ['id', 'date_joined']


class UserProfileSerializer(serializers.ModelSerializer):
    """User profile serializer."""
    
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = ['id', 'user', 'organization', 'role', 'phone', 'is_verified', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class ECUDeviceSerializer(serializers.ModelSerializer):
    """ECU device serializer."""
    
    created_by = UserSerializer(read_only=True)
    
    class Meta:
        model = ECUDevice
        fields = [
            'id', 'name', 'device_type', 'manufacturer', 'model', 'version',
            'description', 'created_by', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_by', 'created_at', 'updated_at']


class FirmwareFileSerializer(serializers.ModelSerializer):
    """Firmware file serializer."""
    
    uploaded_by = UserSerializer(read_only=True)
    ecu_device = ECUDeviceSerializer(read_only=True)
    file_size_mb = serializers.SerializerMethodField()
    
    class Meta:
        model = FirmwareFile
        fields = [
            'id', 'file', 'original_filename', 'file_size', 'file_size_mb',
            'file_hash', 'ecu_device', 'uploaded_by', 'status', 'upload_date', 'analysis_date'
        ]
        read_only_fields = ['id', 'file_size', 'file_hash', 'uploaded_by', 'upload_date', 'analysis_date']
    
    def get_file_size_mb(self, obj):
        """Get file size in MB."""
        if obj.file_size:
            return round(obj.file_size / (1024 * 1024), 2)
        return 0


class ScanResultSerializer(serializers.ModelSerializer):
    """Scan result serializer."""
    
    class Meta:
        model = ScanResult
        fields = ['id', 'result_type', 'result_data', 'confidence_score', 'created_at']
        read_only_fields = ['id', 'created_at']


class VulnerabilitySerializer(serializers.ModelSerializer):
    """Vulnerability serializer."""
    
    scan_session = serializers.PrimaryKeyRelatedField(read_only=True)
    resolved_by = UserSerializer(read_only=True)
    
    class Meta:
        model = Vulnerability
        fields = [
            'id', 'scan_session', 'title', 'description', 'severity', 'status',
            'cve_id', 'cvss_score', 'location', 'evidence', 'recommendations',
            'discovered_at', 'resolved_at', 'resolved_by'
        ]
        read_only_fields = ['id', 'scan_session', 'discovered_at']


class ScanSessionSerializer(serializers.ModelSerializer):
    """Scan session serializer."""
    
    firmware_file = FirmwareFileSerializer(read_only=True)
    initiated_by = UserSerializer(read_only=True)
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    scan_results = ScanResultSerializer(many=True, read_only=True)
    duration = serializers.SerializerMethodField()
    
    class Meta:
        model = ScanSession
        fields = [
            'id', 'firmware_file', 'scan_type', 'status', 'initiated_by',
            'start_time', 'end_time', 'progress', 'scan_config', 'results_summary',
            'vulnerabilities', 'scan_results', 'duration'
        ]
        read_only_fields = ['id', 'initiated_by', 'start_time', 'end_time', 'vulnerabilities', 'scan_results']
    
    def get_duration(self, obj):
        """Calculate scan duration in seconds."""
        if obj.start_time and obj.end_time:
            return (obj.end_time - obj.start_time).total_seconds()
        return None


class FirmwareUploadSerializer(serializers.Serializer):
    """Firmware upload serializer."""
    
    file = serializers.FileField()
    ecu_device_id = serializers.IntegerField(required=False, allow_null=True)
    description = serializers.CharField(required=False, max_length=500)


class StartScanSerializer(serializers.Serializer):
    """Start scan serializer."""
    
    firmware_file_id = serializers.IntegerField()
    scan_type = serializers.ChoiceField(choices=ScanSession.SCAN_TYPES)
    scan_config = serializers.JSONField(required=False, default=dict)


class ScanStatusSerializer(serializers.Serializer):
    """Scan status serializer."""
    
    scan_id = serializers.IntegerField()
    status = serializers.CharField()
    progress = serializers.IntegerField()
    estimated_completion = serializers.DateTimeField(required=False, allow_null=True)


class DashboardStatsSerializer(serializers.Serializer):
    """Dashboard statistics serializer."""
    
    total_scans = serializers.IntegerField()
    total_vulnerabilities = serializers.IntegerField()
    vulnerabilities_by_severity = serializers.DictField()
    recent_scans = ScanSessionSerializer(many=True)
    top_vulnerabilities = VulnerabilitySerializer(many=True)


class AnalysisResultSerializer(serializers.Serializer):
    """Firmware analysis result serializer."""
    
    file_info = serializers.DictField()
    strings = serializers.ListField(child=serializers.CharField())
    entropy = serializers.FloatField()
    patterns = serializers.DictField()
    vulnerabilities = serializers.ListField(child=serializers.DictField())
    elf_analysis = serializers.DictField(required=False)
    pe_analysis = serializers.DictField(required=False)


class MLAnalysisResultSerializer(serializers.Serializer):
    """Machine learning analysis result serializer."""
    
    anomaly_detection = serializers.DictField()
    vulnerability_prediction = serializers.DictField()
    ml_insights = serializers.DictField()


class ExportReportSerializer(serializers.Serializer):
    """Export report serializer."""
    
    scan_id = serializers.IntegerField()
    format = serializers.ChoiceField(choices=['pdf', 'json', 'csv'])
    include_evidence = serializers.BooleanField(default=True)
    include_recommendations = serializers.BooleanField(default=True)
