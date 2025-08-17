#!/bin/bash

# ECUre Setup Script
# This script helps set up the ECUre development environment

set -e

echo "🚗 ECUre Setup Script"
echo "======================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p backend/logs
mkdir -p backend/media
mkdir -p backend/staticfiles
mkdir -p frontend/dist
mkdir -p nginx/conf.d

# Set up environment file
if [ ! -f .env ]; then
    echo "🔧 Creating .env file..."
    cat > .env << EOF
# ECUre Environment Configuration
DEBUG=True
SECRET_KEY=your-secret-key-change-in-production
DB_HOST=localhost
DB_NAME=ecure
DB_USER=ecure
DB_PASSWORD=ecure
DB_PORT=5432
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
ALLOWED_HOSTS=localhost,127.0.0.1
EOF
    echo "✅ .env file created"
else
    echo "✅ .env file already exists"
fi

# Build and start services
echo "🐳 Building and starting Docker services..."
docker-compose up --build -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 30

# Run database migrations
echo "🗄️ Running database migrations..."
docker-compose exec backend python manage.py migrate

# Create superuser
echo "👤 Creating superuser..."
echo "Please enter the following information for the admin user:"
docker-compose exec backend python manage.py createsuperuser

# Collect static files
echo "📦 Collecting static files..."
docker-compose exec backend python manage.py collectstatic --noinput

echo ""
echo "🎉 Setup complete! ECUre is now running."
echo ""
echo "🌐 Access the application:"
echo "   Frontend: http://localhost:3000"
echo "   Backend API: http://localhost:8000"
echo "   Admin Panel: http://localhost:8000/admin"
echo "   API Docs: http://localhost:8000/api/docs"
echo ""
echo "📚 Useful commands:"
echo "   Start services: docker-compose up -d"
echo "   Stop services: docker-compose down"
echo "   View logs: docker-compose logs -f"
echo "   Restart backend: docker-compose restart backend"
echo ""
echo "🔧 For development:"
echo "   Backend logs: docker-compose logs -f backend"
echo "   Frontend logs: docker-compose logs -f frontend"
echo "   Database: docker-compose exec db psql -U ecure -d ecure"
