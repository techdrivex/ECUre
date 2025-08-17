# ECUre Project Structure

This document provides a comprehensive overview of the ECUre project structure, including all files, folders, and their purposes.

## 📁 Root Directory Structure

```
ECUre/
├── LICENSE                          # MIT License file
├── README.md                       # Main project documentation
├── PROJECT_STRUCTURE.md            # This file - detailed project structure
├── .gitignore                      # Git ignore patterns
├── docker-compose.yml              # Docker Compose configuration
├── manage.py                       # Django management script
├── scripts/                        # Setup and utility scripts
│   ├── setup.sh                    # Docker setup script
│   └── dev-setup.sh                # Development setup script
├── backend/                        # Django backend application
├── frontend/                       # React frontend application
└── nginx/                          # Nginx configuration (to be created)
```

## 🐍 Backend (Django) Structure

### Core Django Project
```
backend/
├── requirements.txt                 # Python dependencies
├── Dockerfile                      # Backend Docker configuration
├── init.sql                        # Database initialization script
├── ecure/                          # Main Django project
│   ├── __init__.py                 # Project package
│   ├── settings.py                 # Django settings
│   ├── urls.py                     # Main URL configuration
│   ├── wsgi.py                     # WSGI configuration
│   ├── asgi.py                     # ASGI configuration
│   └── celery.py                   # Celery configuration
├── core/                           # Core application
│   ├── __init__.py                 # App package
│   ├── apps.py                     # App configuration
│   ├── models.py                   # User profiles, system config, audit logs
│   ├── views.py                    # Basic views (home, dashboard, profile)
│   └── urls.py                     # Core app URLs
├── scanner/                        # ECU scanning application
│   ├── __init__.py                 # App package
│   ├── apps.py                     # App configuration
│   └── models.py                   # ECU devices, firmware files, scans, vulnerabilities
├── analysis/                       # Firmware analysis application
│   ├── __init__.py                 # App package
│   ├── apps.py                     # App configuration
│   └── analyzers.py                # Firmware analysis engine
├── ml_engine/                      # Machine learning application
│   ├── __init__.py                 # App package
│   ├── apps.py                     # App configuration
│   └── anomaly_detector.py         # ML-based anomaly detection
├── api/                            # REST API application
│   ├── __init__.py                 # App package
│   ├── apps.py                     # App configuration
│   ├── serializers.py              # API serializers
│   ├── views.py                    # API views and endpoints
│   └── urls.py                     # API URL configuration
├── logs/                           # Application logs (created at runtime)
├── media/                          # Uploaded files (created at runtime)
└── staticfiles/                    # Collected static files (created at runtime)
```

### Backend Features

#### Core App
- **User Management**: Extended user profiles with organization and role information
- **System Configuration**: Centralized configuration management
- **Audit Logging**: Comprehensive security event logging

#### Scanner App
- **ECU Device Management**: Store and manage ECU device information
- **Firmware File Handling**: Upload, store, and track firmware files
- **Scan Sessions**: Manage vulnerability scanning sessions
- **Vulnerability Tracking**: Store and categorize discovered vulnerabilities
- **Scan Results**: Detailed analysis results storage

#### Analysis App
- **Binary Analysis**: Analyze binary firmware files (ELF, PE, raw binary)
- **HEX/S-Record Analysis**: Parse Intel HEX and Motorola S-Record files
- **Pattern Detection**: Find suspicious patterns and sequences
- **String Extraction**: Extract printable strings from binaries
- **Entropy Analysis**: Calculate Shannon entropy for anomaly detection

#### ML Engine App
- **Anomaly Detection**: Isolation Forest-based anomaly detection
- **Vulnerability Prediction**: Machine learning vulnerability likelihood prediction
- **Feature Extraction**: Extract numerical and text features from analysis results
- **Model Management**: Save/load trained ML models

#### API App
- **RESTful Endpoints**: Complete CRUD operations for all models
- **Authentication**: JWT-based authentication system
- **File Upload**: Secure firmware file upload handling
- **Scan Management**: Start, monitor, and retrieve scan results
- **Dashboard Statistics**: Real-time dashboard data
- **Report Export**: Export scan results in multiple formats

## ⚛️ Frontend (React) Structure

```
frontend/
├── package.json                    # Node.js dependencies and scripts
├── Dockerfile                      # Frontend Docker configuration
├── vite.config.ts                  # Vite build configuration
├── tailwind.config.js              # Tailwind CSS configuration
├── postcss.config.js               # PostCSS configuration
├── tsconfig.json                   # TypeScript configuration
├── tsconfig.node.json              # TypeScript node configuration
├── index.html                      # Main HTML file
└── src/                            # Source code
    ├── main.tsx                    # React application entry point
    ├── App.tsx                     # Main App component with routing
    ├── index.css                   # Global styles and Tailwind imports
    ├── components/                 # Reusable UI components
    ├── pages/                      # Page components
    ├── hooks/                      # Custom React hooks
    ├── services/                   # API service functions
    ├── stores/                     # State management (Zustand)
    ├── types/                      # TypeScript type definitions
    └── utils/                      # Utility functions
```

### Frontend Features

#### Technology Stack
- **React 18**: Modern React with hooks and concurrent features
- **TypeScript**: Type-safe development
- **Vite**: Fast build tool and development server
- **Tailwind CSS**: Utility-first CSS framework
- **React Router**: Client-side routing
- **React Query**: Server state management
- **Zustand**: Lightweight state management
- **React Hook Form**: Form handling and validation

#### Key Components
- **Layout**: Main application layout with navigation
- **Dashboard**: Overview of scans, vulnerabilities, and statistics
- **Scanner**: Firmware upload and scan initiation
- **Analysis**: View detailed analysis results
- **Vulnerabilities**: Browse and manage discovered vulnerabilities
- **Reports**: Generate and export scan reports
- **Profile**: User profile management

## 🐳 Docker Configuration

### Services
- **PostgreSQL 15**: Primary database
- **Redis 7**: Message broker for Celery
- **Django Backend**: Main application server
- **Celery Worker**: Background task processing
- **Celery Beat**: Scheduled task management
- **React Frontend**: User interface
- **Nginx**: Reverse proxy and static file serving

### Volumes
- **postgres_data**: Persistent database storage
- **media_files**: Uploaded firmware files
- **static_files**: Collected static assets

## 🚀 Getting Started

### Quick Start with Docker
```bash
# Clone the repository
git clone https://github.com/yourusername/ECUre.git
cd ECUre

# Make setup script executable
chmod +x scripts/setup.sh

# Run setup script
./scripts/setup.sh
```

### Development Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/ECUre.git
cd ECUre

# Make development setup script executable
chmod +x scripts/dev-setup.sh

# Run development setup
./scripts/dev-setup.sh
```

## 🔧 Development Commands

### Backend
```bash
cd backend

# Activate virtual environment
source ../venv/bin/activate

# Run development server
python manage.py runserver

# Run tests
python manage.py test

# Make migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Start Celery worker
celery -A ecure worker --loglevel=info

# Start Celery beat
celery -A ecure beat --loglevel=info
```

### Frontend
```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Run linting
npm run lint

# Fix linting issues
npm run lint:fix

# Type checking
npm run type-check
```

### Docker
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down

# Rebuild and start
docker-compose up --build -d

# Access specific service
docker-compose exec backend python manage.py shell
docker-compose exec db psql -U ecure -d ecure
```

## 📊 API Endpoints

### Authentication
- `POST /api/v1/auth/token/` - Obtain JWT token
- `POST /api/v1/auth/token/refresh/` - Refresh JWT token

### Core Resources
- `GET /api/v1/users/` - List users
- `GET /api/v1/ecu-devices/` - List ECU devices
- `GET /api/v1/firmware-files/` - List firmware files
- `GET /api/v1/scan-sessions/` - List scan sessions
- `GET /api/v1/vulnerabilities/` - List vulnerabilities

### Custom Endpoints
- `POST /api/v1/upload-firmware/` - Upload firmware file
- `POST /api/v1/start-scan/` - Start vulnerability scan
- `GET /api/v1/scan-status/{id}/` - Get scan status
- `GET /api/v1/scan-results/{id}/` - Get scan results
- `GET /api/v1/dashboard-stats/` - Get dashboard statistics
- `POST /api/v1/analyze-firmware/{id}/` - Analyze firmware
- `POST /api/v1/ml-analysis/{id}/` - Perform ML analysis
- `POST /api/v1/export-report/{id}/` - Export scan report

### API Documentation
- `GET /api/schema/` - OpenAPI schema
- `GET /api/docs/` - Interactive API documentation

## 🗄️ Database Schema

### Core Models
- **UserProfile**: Extended user information
- **SystemConfiguration**: System-wide settings
- **AuditLog**: Security event logging

### Scanner Models
- **ECUDevice**: ECU device information
- **FirmwareFile**: Firmware file storage
- **ScanSession**: Vulnerability scanning sessions
- **Vulnerability**: Discovered vulnerabilities
- **ScanResult**: Detailed scan results

### Key Relationships
- Users can have multiple ECU devices
- ECU devices can have multiple firmware files
- Firmware files can have multiple scan sessions
- Scan sessions can have multiple vulnerabilities
- Scan sessions can have multiple scan results

## 🔒 Security Features

- **JWT Authentication**: Secure token-based authentication
- **CORS Protection**: Cross-origin request protection
- **File Validation**: Secure firmware file uploads
- **Audit Logging**: Comprehensive security event tracking
- **Input Validation**: Server-side input sanitization
- **SQL Injection Protection**: Django ORM protection
- **XSS Protection**: Content Security Policy headers

## 📈 Performance Features

- **Database Indexing**: Optimized database queries
- **Caching**: Redis-based caching for frequently accessed data
- **Background Processing**: Celery for long-running tasks
- **Static File Serving**: Nginx for efficient static file delivery
- **API Pagination**: Efficient data retrieval
- **Database Views**: Pre-computed statistics and summaries

## 🧪 Testing

### Backend Testing
- **Unit Tests**: Django test framework
- **Integration Tests**: API endpoint testing
- **Model Tests**: Database model validation
- **Security Tests**: Authentication and authorization testing

### Frontend Testing
- **Component Tests**: React component testing
- **Integration Tests**: User interaction testing
- **E2E Tests**: End-to-end workflow testing

## 📝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the API documentation at `/api/docs/`
- Review the project README
- Contact the development team

## 🔮 Future Enhancements

- **Live CAN Bus Testing**: Real-time ECU communication testing
- **Plugin System**: Community-driven vulnerability detection rules
- **CI/CD Integration**: Automated testing and deployment
- **Advanced ML Models**: Deep learning for vulnerability detection
- **Mobile Application**: iOS and Android apps
- **Cloud Deployment**: AWS, Azure, and GCP deployment guides
- **API Rate Limiting**: Advanced API usage controls
- **Multi-language Support**: Internationalization features
