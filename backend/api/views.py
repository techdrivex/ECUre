"""
API views for ECUre application.
"""

import os
import hashlib
from django.shortcuts import get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from django.db.models import Count, Q
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile

from .serializers import (
    UserSerializer, ECUDeviceSerializer, FirmwareFileSerializer,
    ScanSessionSerializer, VulnerabilitySerializer, FirmwareUploadSerializer,
    StartScanSerializer, ScanStatusSerializer, DashboardStatsSerializer,
    AnalysisResultSerializer, MLAnalysisResultSerializer, ExportReportSerializer
)
from core.models import UserProfile
from scanner.models import ECUDevice, FirmwareFile, ScanSession, Vulnerability, ScanResult
from analysis.analyzers import FirmwareAnalyzer
from ml_engine.anomaly_detector import MLEngine
from core.models import AuditLog


class UserViewSet(viewsets.ReadOnlyModelViewSet):
    """User viewset."""
    
    queryset = UserProfile.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Filter queryset based on user permissions."""
        if self.request.user.is_staff:
            return UserProfile.objects.all()
        return UserProfile.objects.filter(user=self.request.user)


class ECUDeviceViewSet(viewsets.ModelViewSet):
    """ECU device viewset."""
    
    queryset = ECUDevice.objects.all()
    serializer_class = ECUDeviceSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def perform_create(self, serializer):
        """Set the created_by field."""
        serializer.save(created_by=self.request.user)
    
    def get_queryset(self):
        """Filter queryset based on user."""
        return ECUDevice.objects.filter(created_by=self.request.user)


class FirmwareFileViewSet(viewsets.ModelViewSet):
    """Firmware file viewset."""
    
    queryset = FirmwareFile.objects.all()
    serializer_class = FirmwareFileSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    
    def perform_create(self, serializer):
        """Set the uploaded_by field and calculate hash."""
        firmware_file = serializer.save(uploaded_by=self.request.user)
        
        # Calculate file hash
        file_path = firmware_file.file.path
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        firmware_file.file_hash = file_hash
        firmware_file.save()
        
        # Log the action
        AuditLog.objects.create(
            user=self.request.user,
            action='FILE_UPLOAD',
            details={'file_id': firmware_file.id, 'filename': firmware_file.original_filename},
            ip_address=self.request.META.get('REMOTE_ADDR'),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )
    
    def get_queryset(self):
        """Filter queryset based on user."""
        return FirmwareFile.objects.filter(uploaded_by=self.request.user)


class ScanSessionViewSet(viewsets.ModelViewSet):
    """Scan session viewset."""
    
    queryset = ScanSession.objects.all()
    serializer_class = ScanSessionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def perform_create(self, serializer):
        """Set the initiated_by field."""
        serializer.save(initiated_by=self.request.user)
    
    def get_queryset(self):
        """Filter queryset based on user."""
        return ScanSession.objects.filter(initiated_by=self.request.user)


class VulnerabilityViewSet(viewsets.ModelViewSet):
    """Vulnerability viewset."""
    
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Filter queryset based on user's scan sessions."""
        user_scan_sessions = ScanSession.objects.filter(initiated_by=self.request.user)
        return Vulnerability.objects.filter(scan_session__in=user_scan_sessions)


class FirmwareUploadView(APIView):
    """Handle firmware file uploads."""
    
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Upload firmware file."""
        serializer = FirmwareUploadSerializer(data=request.data)
        if serializer.is_valid():
            try:
                file_obj = request.FILES['file']
                ecu_device_id = serializer.validated_data.get('ecu_device_id')
                
                # Create firmware file record
                firmware_file = FirmwareFile.objects.create(
                    file=file_obj,
                    original_filename=file_obj.name,
                    uploaded_by=request.user,
                    ecu_device_id=ecu_device_id
                )
                
                # Calculate file hash
                file_path = firmware_file.file.path
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                firmware_file.file_hash = file_hash
                firmware_file.save()
                
                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='FILE_UPLOAD',
                    details={'file_id': firmware_file.id, 'filename': firmware_file.original_filename},
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                return Response({
                    'message': 'Firmware uploaded successfully',
                    'file_id': firmware_file.id,
                    'file_hash': file_hash
                }, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                return Response({
                    'error': f'Upload failed: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class StartScanView(APIView):
    """Start a new firmware scan."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Start firmware scanning."""
        serializer = StartScanSerializer(data=request.data)
        if serializer.is_valid():
            try:
                firmware_file_id = serializer.validated_data['firmware_file_id']
                scan_type = serializer.validated_data['scan_type']
                scan_config = serializer.validated_data.get('scan_config', {})
                
                # Get firmware file
                firmware_file = get_object_or_404(FirmwareFile, id=firmware_file_id, uploaded_by=request.user)
                
                # Create scan session
                scan_session = ScanSession.objects.create(
                    firmware_file=firmware_file,
                    scan_type=scan_type,
                    scan_config=scan_config,
                    initiated_by=request.user,
                    status='PENDING'
                )
                
                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='SCAN_START',
                    details={'scan_id': scan_session.id, 'scan_type': scan_type},
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                # TODO: Start background scan task using Celery
                # start_scan_task.delay(scan_session.id)
                
                return Response({
                    'message': 'Scan started successfully',
                    'scan_id': scan_session.id,
                    'status': scan_session.status
                }, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                return Response({
                    'error': f'Failed to start scan: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScanStatusView(APIView):
    """Get scan status and progress."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, scan_id):
        """Get scan status."""
        try:
            scan_session = get_object_or_404(ScanSession, id=scan_id, initiated_by=request.user)
            
            return Response({
                'scan_id': scan_session.id,
                'status': scan_session.status,
                'progress': scan_session.progress,
                'start_time': scan_session.start_time,
                'end_time': scan_session.end_time,
                'scan_type': scan_session.scan_type
            })
            
        except Exception as e:
            return Response({
                'error': f'Failed to get scan status: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ScanResultsView(APIView):
    """Get scan results and vulnerabilities."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, scan_id):
        """Get scan results."""
        try:
            scan_session = get_object_or_404(ScanSession, id=scan_id, initiated_by=request.user)
            
            # Get vulnerabilities
            vulnerabilities = Vulnerability.objects.filter(scan_session=scan_session)
            vulnerability_serializer = VulnerabilitySerializer(vulnerabilities, many=True)
            
            # Get scan results
            scan_results = ScanResult.objects.filter(scan_session=scan_session)
            scan_result_serializer = ScanResultSerializer(scan_results, many=True)
            
            return Response({
                'scan_id': scan_session.id,
                'status': scan_session.status,
                'vulnerabilities': vulnerability_serializer.data,
                'scan_results': scan_result_serializer.data,
                'results_summary': scan_session.results_summary
            })
            
        except Exception as e:
            return Response({
                'error': f'Failed to get scan results: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DashboardStatsView(APIView):
    """Get dashboard statistics."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get dashboard statistics."""
        try:
            user = request.user
            
            # Get user's scan sessions
            user_scans = ScanSession.objects.filter(initiated_by=user)
            
            # Calculate statistics
            total_scans = user_scans.count()
            total_vulnerabilities = Vulnerability.objects.filter(scan_session__in=user_scans).count()
            
            # Vulnerabilities by severity
            vulnerabilities_by_severity = Vulnerability.objects.filter(
                scan_session__in=user_scans
            ).values('severity').annotate(count=Count('id'))
            
            severity_counts = {item['severity']: item['count'] for item in vulnerabilities_by_severity}
            
            # Recent scans
            recent_scans = user_scans.order_by('-start_time')[:5]
            recent_scans_serializer = ScanSessionSerializer(recent_scans, many=True)
            
            # Top vulnerabilities
            top_vulnerabilities = Vulnerability.objects.filter(
                scan_session__in=user_scans
            ).order_by('-severity', '-discovered_at')[:10]
            top_vulns_serializer = VulnerabilitySerializer(top_vulnerabilities, many=True)
            
            return Response({
                'total_scans': total_scans,
                'total_vulnerabilities': total_vulnerabilities,
                'vulnerabilities_by_severity': severity_counts,
                'recent_scans': recent_scans_serializer.data,
                'top_vulnerabilities': top_vulns_serializer.data
            })
            
        except Exception as e:
            return Response({
                'error': f'Failed to get dashboard stats: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AnalyzeFirmwareView(APIView):
    """Analyze firmware file."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, file_id):
        """Analyze firmware file."""
        try:
            firmware_file = get_object_or_404(FirmwareFile, id=file_id, uploaded_by=request.user)
            
            # Perform firmware analysis
            analyzer = FirmwareAnalyzer(firmware_file.file.path)
            analysis_results = analyzer.analyze()
            
            # Update firmware file status
            firmware_file.status = 'ANALYZED'
            firmware_file.analysis_date = timezone.now()
            firmware_file.save()
            
            return Response(analysis_results, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': f'Analysis failed: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class MLAnalysisView(APIView):
    """Perform machine learning analysis on firmware."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, file_id):
        """Perform ML analysis."""
        try:
            firmware_file = get_object_or_404(FirmwareFile, id=file_id, uploaded_by=request.user)
            
            # First perform basic analysis
            analyzer = FirmwareAnalyzer(firmware_file.file.path)
            analysis_results = analyzer.analyze()
            
            # Perform ML analysis
            ml_engine = MLEngine()
            ml_results = ml_engine.analyze_firmware(analysis_results)
            
            return Response(ml_results, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': f'ML analysis failed: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ExportReportView(APIView):
    """Export scan report."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, scan_id):
        """Export scan report."""
        serializer = ExportReportSerializer(data=request.data)
        if serializer.is_valid():
            try:
                scan_session = get_object_or_404(ScanSession, id=scan_id, initiated_by=request.user)
                export_format = serializer.validated_data['format']
                
                # TODO: Implement report generation based on format
                if export_format == 'json':
                    # Return JSON report
                    vulnerabilities = Vulnerability.objects.filter(scan_session=scan_session)
                    vuln_serializer = VulnerabilitySerializer(vulnerabilities, many=True)
                    
                    report = {
                        'scan_id': scan_session.id,
                        'scan_type': scan_session.scan_type,
                        'start_time': scan_session.start_time,
                        'end_time': scan_session.end_time,
                        'vulnerabilities': vuln_serializer.data,
                        'summary': scan_session.results_summary
                    }
                    
                    return Response(report, status=status.HTTP_200_OK)
                
                elif export_format == 'csv':
                    # TODO: Generate CSV report
                    return Response({
                        'message': 'CSV export not yet implemented'
                    }, status=status.HTTP_501_NOT_IMPLEMENTED)
                
                elif export_format == 'pdf':
                    # TODO: Generate PDF report
                    return Response({
                        'message': 'PDF export not yet implemented'
                    }, status=status.HTTP_501_NOT_IMPLEMENTED)
                
                else:
                    return Response({
                        'error': 'Unsupported export format'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
            except Exception as e:
                return Response({
                    'error': f'Export failed: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
