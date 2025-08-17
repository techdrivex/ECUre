#!/bin/bash

# ECUre Development Setup Script
# This script sets up the ECUre development environment without Docker

set -e

echo "🚗 ECUre Development Setup Script"
echo "================================="

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
required_version="3.11"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python 3.11+ is required. Current version: $python_version"
    exit 1
fi

echo "✅ Python version: $python_version"

# Check Node.js version
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 16+ first."
    exit 1
fi

node_version=$(node --version | cut -d'v' -f2 | cut -d. -f1)
if [ "$node_version" -lt 16 ]; then
    echo "❌ Node.js 16+ is required. Current version: $(node --version)"
    exit 1
fi

echo "✅ Node.js version: $(node --version)"

# Check if PostgreSQL is running
if ! pg_isready -q; then
    echo "❌ PostgreSQL is not running. Please start PostgreSQL first."
    exit 1
fi

echo "✅ PostgreSQL is running"

# Create virtual environment
echo "🐍 Creating Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install Python dependencies
echo "📦 Installing Python dependencies..."
cd backend
pip install --upgrade pip
pip install -r requirements.txt
cd ..

# Install Node.js dependencies
echo "📦 Installing Node.js dependencies..."
cd frontend
npm install
cd ..

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p backend/logs
mkdir -p backend/media
mkdir -p backend/staticfiles

# Set up environment file
if [ ! -f .env ]; then
    echo "🔧 Creating .env file..."
    cat > .env << EOF
# ECUre Development Environment Configuration
DEBUG=True
SECRET_KEY=dev-secret-key-change-in-production
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

# Create database
echo "🗄️ Creating database..."
createdb ecure 2>/dev/null || echo "Database 'ecure' already exists"

# Run database migrations
echo "🗄️ Running database migrations..."
cd backend
python manage.py migrate
cd ..

# Create superuser
echo "👤 Creating superuser..."
echo "Please enter the following information for the admin user:"
cd backend
python manage.py createsuperuser
cd ..

# Collect static files
echo "📦 Collecting static files..."
cd backend
python manage.py collectstatic --noinput
cd ..

echo ""
echo "🎉 Development setup complete!"
echo ""
echo "🌐 To start the application:"
echo ""
echo "1. Start the backend (in one terminal):"
echo "   cd backend"
echo "   source ../venv/bin/activate"
echo "   python manage.py runserver"
echo ""
echo "2. Start the frontend (in another terminal):"
echo "   cd frontend"
echo "   npm run dev"
echo ""
echo "3. Start Redis (if not running):"
echo "   redis-server"
echo ""
echo "4. Start Celery (in another terminal):"
echo "   cd backend"
echo "   source ../venv/bin/activate"
echo "   celery -A ecure worker --loglevel=info"
echo ""
echo "🌐 Access the application:"
echo "   Frontend: http://localhost:3000"
echo "   Backend API: http://localhost:8000"
echo "   Admin Panel: http://localhost:8000/admin"
echo "   API Docs: http://localhost:8000/api/docs"
echo ""
echo "📚 Useful commands:"
echo "   Activate venv: source venv/bin/activate"
echo "   Run tests: python manage.py test"
echo "   Make migrations: python manage.py makemigrations"
echo "   Shell: python manage.py shell"
