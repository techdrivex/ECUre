"""
URL configuration for API app.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'ecu-devices', views.ECUDeviceViewSet)
router.register(r'firmware-files', views.FirmwareFileViewSet)
router.register(r'scan-sessions', views.ScanSessionViewSet)
router.register(r'vulnerabilities', views.VulnerabilityViewSet)
router.register(r'users', views.UserViewSet)

app_name = 'api'

urlpatterns = [
    # Authentication
    path('auth/', include('rest_framework_simplejwt.urls')),
    
    # API endpoints
    path('', include(router.urls)),
    
    # Custom endpoints
    path('upload-firmware/', views.FirmwareUploadView.as_view(), name='upload-firmware'),
    path('start-scan/', views.StartScanView.as_view(), name='start-scan'),
    path('scan-status/<int:scan_id>/', views.ScanStatusView.as_view(), name='scan-status'),
    path('scan-results/<int:scan_id>/', views.ScanResultsView.as_view(), name='scan-results'),
    path('dashboard-stats/', views.DashboardStatsView.as_view(), name='dashboard-stats'),
    
    # Analysis endpoints
    path('analyze-firmware/<int:file_id>/', views.AnalyzeFirmwareView.as_view(), name='analyze-firmware'),
    path('ml-analysis/<int:file_id>/', views.MLAnalysisView.as_view(), name='ml-analysis'),
    
    # Export endpoints
    path('export-report/<int:scan_id>/', views.ExportReportView.as_view(), name='export-report'),
]
