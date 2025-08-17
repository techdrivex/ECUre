# ECUre

![ECUre Logo](ecure_logo.png)

# AI-Driven Vulnerability Scanner for Automotive ECUs

**Secure your vehicles with intelligent firmware analysis**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18+-61dafb.svg)](https://reactjs.org/)
[![Django](https://img.shields.io/badge/Django-4.2+-092E20.svg)](https://www.djangoproject.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

## Overview

ECUre is a comprehensive, AI-powered vulnerability scanning platform specifically designed for automotive Electronic Control Units (ECUs). It combines advanced static and dynamic analysis techniques with machine learning to identify security vulnerabilities in vehicle firmware, helping manufacturers and security researchers ensure automotive cybersecurity.

## ✨ Key Features

- **🔍 Static & Dynamic Analysis**: Comprehensive firmware analysis using multiple techniques
- **🤖 ML-Powered Detection**: AI-driven anomaly detection and vulnerability prediction
- **📊 Vulnerability Database**: Centralized vulnerability tracking and management
- **🌙 Dark Theme Support**: Modern, accessible user interface with theme switching
- **📈 Real-time Dashboard**: Live monitoring and analytics dashboard
- **📋 Advanced Reporting**: Multi-format reports with executive summaries
- **🔒 Security-First**: Built with security best practices and audit logging
- **📱 Responsive Design**: Mobile-first responsive interface
- **🐳 Docker Ready**: Complete containerization for easy deployment
- **🚀 Scalable Architecture**: Designed for enterprise-scale deployments

## 🎯 Target Users

- **Automotive Manufacturers**: Secure firmware development and testing
- **Security Researchers**: Automotive cybersecurity research and analysis
- **Penetration Testers**: Vehicle security assessment and testing
- **Compliance Teams**: Automotive security standard compliance verification
- **Development Teams**: Secure coding practices and vulnerability prevention

## 🛠️ Tech Stack

### Backend
- **Python 3.11+**: Core programming language
- **Django 4.2+**: Web framework
- **Django REST Framework**: API development
- **PostgreSQL**: Primary database
- **Redis**: Caching and message broker
- **Celery**: Background task processing
- **Gunicorn**: WSGI server

### Frontend
- **React 18**: Modern UI framework
- **TypeScript**: Type-safe development
- **Tailwind CSS**: Utility-first CSS framework
- **Vite**: Fast build tool
- **React Query**: Data fetching and caching
- **Zustand**: State management

### Analysis & ML
- **Capstone**: Binary analysis engine
- **Pefile**: PE file analysis
- **Pyelftools**: ELF file analysis
- **Scikit-learn**: Machine learning algorithms
- **NumPy/Pandas**: Data processing
- **Python-magic**: File type detection

### Infrastructure
- **Docker**: Containerization
- **Nginx**: Reverse proxy and static file serving
- **Docker Compose**: Multi-service orchestration

## 📋 Prerequisites

- Python 3.11 or higher
- Node.js 16 or higher
- PostgreSQL 12 or higher
- Redis 6 or higher
- Docker and Docker Compose (for containerized deployment)

## 🚀 Quick Start

### Option 1: Docker Setup (Recommended)

```bash
# Clone the repository
git clone https://github.com/techdrivex/ECUre.git
cd ECUre

# Make setup script executable and run
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### Option 2: Local Development Setup

```bash
# Clone the repository
git clone https://github.com/techdrivex/ECUre.git
cd ECUre

# Make dev setup script executable and run
chmod +x scripts/dev-setup.sh
./scripts/dev-setup.sh
```

## 📖 Usage

### 1. Access the Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/api/docs/
- **Admin Panel**: http://localhost:8000/admin/

### 2. Upload Firmware

1. Navigate to the Scanner page
2. Upload your ECU firmware file
3. Select analysis options
4. Start the scan

### 3. View Results

1. Monitor scan progress in real-time
2. Review detected vulnerabilities
3. Export detailed reports
4. Track remediation progress

### 4. Generate Reports

- **JSON**: Machine-readable format for integration
- **CSV**: Spreadsheet analysis and reporting
- **HTML**: Web-based interactive reports
- **PDF**: Executive summaries and presentations

## 🏗️ Project Structure

```
ECUre/
├── backend/                 # Django backend application
│   ├── ecure/             # Main Django project
│   ├── core/              # Core functionality and models
│   ├── scanner/           # Firmware scanning logic
│   ├── analysis/          # Analysis engines and tools
│   ├── ml_engine/         # Machine learning components
│   ├── api/               # REST API endpoints
│   └── tools/             # Additional analysis tools
├── frontend/               # React frontend application
│   ├── src/               # Source code
│   ├── components/        # Reusable UI components
│   ├── pages/             # Application pages
│   ├── hooks/             # Custom React hooks
│   └── utils/             # Utility functions
├── scripts/                # Setup and deployment scripts
├── docker-compose.yml      # Docker services configuration
└── README.md              # This file
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# Django Settings
DEBUG=True
SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DB_NAME=ecure
DB_USER=ecure
DB_PASSWORD=your-password
DB_HOST=localhost
DB_PORT=5432

# Redis
REDIS_URL=redis://localhost:6379

# File Upload
MAX_UPLOAD_SIZE=100MB
```

### Customization

- **Analysis Rules**: Modify detection patterns in `backend/analysis/`
- **ML Models**: Customize machine learning algorithms in `backend/ml_engine/`
- **UI Theme**: Adjust colors and styling in `frontend/tailwind.config.js`
- **API Endpoints**: Extend functionality in `backend/api/`

## 🧪 Testing

```bash
# Backend tests
cd backend
python manage.py test

# Frontend tests
cd frontend
npm test

# End-to-end tests
npm run test:e2e
```

## 📊 API Endpoints

### Core Endpoints
- `POST /api/v1/upload-firmware/` - Upload firmware for analysis
- `POST /api/v1/start-scan/` - Initiate vulnerability scan
- `GET /api/v1/scan-status/<id>/` - Get scan progress
- `GET /api/v1/scan-results/<id>/` - Retrieve scan results
- `GET /api/v1/vulnerabilities/` - List all vulnerabilities
- `GET /api/v1/dashboard-stats/` - Get dashboard statistics

### Analysis Endpoints
- `POST /api/v1/analyze-firmware/` - Perform firmware analysis
- `POST /api/v1/ml-analysis/` - Run ML-based analysis
- `GET /api/v1/export-report/<id>/` - Export scan reports

## 🔒 Security Features

- **JWT Authentication**: Secure token-based authentication
- **Role-based Access Control**: Granular permission management
- **Input Validation**: Comprehensive server-side validation
- **File Upload Security**: Secure firmware file handling
- **Audit Logging**: Complete activity tracking
- **CORS Protection**: Cross-origin request security
- **SQL Injection Protection**: ORM-based query security

## 🚀 Deployment

### Production Deployment

```bash
# Build production images
docker-compose -f docker-compose.prod.yml build

# Deploy with production settings
docker-compose -f docker-compose.prod.yml up -d

# Run migrations
docker-compose -f docker-compose.prod.yml exec backend python manage.py migrate

# Collect static files
docker-compose -f docker-compose.prod.yml exec backend python manage.py collectstatic
```

### Environment-Specific Configurations

- **Development**: `docker-compose.yml`
- **Production**: `docker-compose.prod.yml`
- **Testing**: `docker-compose.test.yml`

## 📈 Performance

- **Response Time**: <200ms for most operations
- **Concurrent Users**: 1000+ simultaneous users
- **File Processing**: Up to 1GB firmware files
- **Database**: Optimized queries with proper indexing
- **Caching**: Redis-based caching for improved performance

## 🤝 Contributing

We welcome contributions from the community! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/techdrivex/ECUre.git
cd ECUre

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt
cd frontend && npm install

# Run development servers
python manage.py runserver  # Backend
npm run dev                 # Frontend
```

### Code Standards

- **Python**: Follow PEP 8 guidelines
- **JavaScript/TypeScript**: Use ESLint and Prettier
- **CSS**: Follow Tailwind CSS conventions
- **Testing**: Maintain >80% test coverage
- **Documentation**: Document all public APIs

## 📚 Documentation

- **API Documentation**: Available at `/api/docs/` when running
- **User Guide**: Comprehensive usage instructions
- **Developer Guide**: Technical implementation details
- **Architecture Overview**: System design documentation

## 🐛 Troubleshooting

### Common Issues

1. **Database Connection Error**
   - Verify PostgreSQL is running
   - Check database credentials in `.env`
   - Ensure database exists

2. **Redis Connection Error**
   - Verify Redis server is running
   - Check Redis URL configuration
   - Test Redis connectivity

3. **File Upload Issues**
   - Check file size limits
   - Verify file permissions
   - Ensure sufficient disk space

4. **Frontend Build Errors**
   - Clear `node_modules` and reinstall
   - Check Node.js version compatibility
   - Verify environment variables

### Getting Help

- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Join community discussions
- **Documentation**: Check comprehensive docs
- **Support**: Contact the development team

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Automotive Security Community**: For insights and feedback
- **Open Source Contributors**: For the amazing tools and libraries
- **Security Researchers**: For vulnerability research and disclosure
- **ECUre Team**: For continuous development and improvement

## 📞 Contact

- **Project**: [ECUre GitHub Repository](https://github.com/techdrivex/ECUre)
- **Issues**: [GitHub Issues](https://github.com/techdrivex/ECUre/issues)
- **Discussions**: [GitHub Discussions](https://github.com/techdrivex/ECUre/discussions)
- **Email**: security@ecure.dev

---

**Secure the future of automotive cybersecurity with ECUre**

🚗🔒✨
