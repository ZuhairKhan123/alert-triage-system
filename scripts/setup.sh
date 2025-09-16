#!/bin/bash

# Alert Triage System - Setup Script
# This script sets up the development environment for the Alert Triage System

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PYTHON_VERSION="3.11"
PROJECT_NAME="alert-triage-system"
VENV_NAME="alert-triage-env"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python_version() {
    if command_exists python3; then
        PYTHON_VER=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        if [ "$(printf '%s\n' "$PYTHON_VERSION" "$PYTHON_VER" | sort -V | head -n1)" = "$PYTHON_VERSION" ]; then
            print_success "Python $PYTHON_VER found (required: $PYTHON_VERSION+)"
            return 0
        else
            print_error "Python $PYTHON_VER found, but $PYTHON_VERSION+ is required"
            return 1
        fi
    else
        print_error "Python 3 not found"
        return 1
    fi
}

# Function to create virtual environment
create_venv() {
    print_status "Creating virtual environment: $VENV_NAME"
    
    if [ -d "$VENV_NAME" ]; then
        print_warning "Virtual environment already exists. Removing..."
        rm -rf "$VENV_NAME"
    fi
    
    python3 -m venv "$VENV_NAME"
    source "$VENV_NAME/bin/activate"
    
    # Upgrade pip
    print_status "Upgrading pip..."
    pip install --upgrade pip
    
    print_success "Virtual environment created and activated"
}

# Function to install Python dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."
    
    # Install production dependencies
    if [ -f "requirements.txt" ]; then
        print_status "Installing production requirements..."
        pip install -r requirements.txt
    else
        print_error "requirements.txt not found"
        return 1
    fi
    
    # Install development dependencies if available
    if [ -f "requirements-dev.txt" ]; then
        print_status "Installing development requirements..."
        pip install -r requirements-dev.txt
    else
        print_warning "requirements-dev.txt not found, skipping development dependencies"
    fi
    
    print_success "Python dependencies installed"
}

# Function to setup pre-commit hooks
setup_pre_commit() {
    if command_exists pre-commit; then
        print_status "Setting up pre-commit hooks..."
        pre-commit install
        print_success "Pre-commit hooks installed"
    else
        print_warning "pre-commit not available, skipping hook setup"
    fi
}

# Function to create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    directories=(
        "logs"
        "data/models"
        "data/training"
        "data/reference"
        "backups"
        "monitoring/grafana/dashboards"
        "monitoring/prometheus"
    )
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            print_status "Created directory: $dir"
        fi
    done
    
    print_success "Directories created"
}

# Function to setup configuration files
setup_config() {
    print_status "Setting up configuration files..."
    
    # Create .env file from template
    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            cp .env.example .env
            print_status "Created .env file from template"
        else
            cat > .env << EOF
# Alert Triage System Environment Variables

# Environment
ENVIRONMENT=development
LOG_LEVEL=INFO

# Security
WEBHOOK_SECRET=dev-webhook-secret-change-in-production
JWT_SECRET=dev-jwt-secret-change-in-production
API_KEY_REQUIRED=false

# Database
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=alert_triage
POSTGRES_USERNAME=alerttriage
POSTGRES_PASSWORD=

# External Integrations (disabled by default)
SIEM_ENABLED=false
SOAR_ENABLED=false
THREAT_INTEL_ENABLED=false

# Features
ENABLE_AUTOMATION=true
ML_ENABLED=false
NOTIFICATIONS_ENABLED=false
EOF
            print_status "Created default .env file"
        fi
    else
        print_warning ".env file already exists, skipping"
    fi
    
    print_success "Configuration setup complete"
}

# Function to run initial tests
run_tests() {
    print_status "Running initial tests..."
    
    if command_exists pytest; then
        # Run a subset of tests to verify setup
        if [ -d "tests" ]; then
            python -m pytest tests/unit/test_agents/test_alert_receiver.py -v
            print_success "Initial tests passed"
        else
            print_warning "Tests directory not found, skipping test run"
        fi
    else
        print_warning "pytest not available, skipping test run"
    fi
}

# Function to check external dependencies
check_external_deps() {
    print_status "Checking external dependencies..."
    
    # Check for Docker
    if command_exists docker; then
        print_success "Docker found"
        
        # Check if Docker daemon is running
        if docker info >/dev/null 2>&1; then
            print_success "Docker daemon is running"
        else
            print_warning "Docker daemon is not running"
        fi
    else
        print_warning "Docker not found (optional for development)"
    fi
    
    # Check for Docker Compose
    if command_exists docker-compose; then
        print_success "Docker Compose found"
    else
        print_warning "Docker Compose not found (optional for development)"
    fi
    
    # Check for kubectl (if using Kubernetes)
    if command_exists kubectl; then
        print_success "kubectl found"
    else
        print_warning "kubectl not found (optional for Kubernetes deployment)"
    fi
}

# Function to setup development tools
setup_dev_tools() {
    print_status "Setting up development tools..."
    
    # Create useful development scripts
    mkdir -p scripts/dev
    
    # Create a script to run the system in development mode
    cat > scripts/dev/run_dev.sh << 'EOF'
#!/bin/bash
# Run the Alert Triage System in development mode

echo "Starting Alert Triage System in development mode..."

# Activate virtual environment if it exists
if [ -d "alert-triage-env" ]; then
    source alert-triage-env/bin/activate
fi

# Set development environment
export ENVIRONMENT=development
export LOG_LEVEL=DEBUG

# Run the system
python src/main.py demo
EOF
    chmod +x scripts/dev/run_dev.sh
    
    # Create a script to run tests
    cat > scripts/dev/run_tests.sh << 'EOF'
#!/bin/bash
# Run tests for the Alert Triage System

echo "Running Alert Triage System tests..."

# Activate virtual environment if it exists
if [ -d "alert-triage-env" ]; then
    source alert-triage-env/bin/activate
fi

# Run tests with coverage
python -m pytest tests/ -v --cov=src/ --cov-report=html --cov-report=term

echo "Coverage report generated in htmlcov/"
EOF
    chmod +x scripts/dev/run_tests.sh
    
    # Create a script to send test alerts
    cat > scripts/dev/send_test_alert.sh << 'EOF'
#!/bin/bash
# Send a test alert to the webhook

WEBHOOK_URL="${1:-http://localhost:8080/webhook/alert}"

echo "Sending test alert to: $WEBHOOK_URL"

curl -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-'$(date +%s)'",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "source_system": "test_script",
    "type": "brute_force",
    "description": "Test alert from setup script",
    "source_ip": "203.0.113.45",
    "user_id": "test_user"
  }'

echo
echo "Test alert sent!"
EOF
    chmod +x scripts/dev/send_test_alert.sh
    
    print_success "Development tools setup complete"
}

# Function to display next steps
show_next_steps() {
    print_success "Setup completed successfully!"
    echo
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Activate the virtual environment:"
    echo "   source $VENV_NAME/bin/activate"
    echo
    echo "2. Start the system in development mode:"
    echo "   python src/main.py demo"
    echo "   or use: ./scripts/dev/run_dev.sh"
    echo
    echo "3. In another terminal, test the webhook:"
    echo "   ./scripts/dev/send_test_alert.sh"
    echo
    echo "4. Run tests:"
    echo "   ./scripts/dev/run_tests.sh"
    echo
    echo "5. Start with Docker Compose (optional):"
    echo "   docker-compose up -d"
    echo
    echo -e "${BLUE}Useful URLs:${NC}"
    echo "- Webhook endpoint: http://localhost:8080/webhook/alert"
    echo "- Health check: http://localhost:8080/health"
    echo "- Metrics: http://localhost:9090/metrics"
    echo "- Grafana (if using Docker): http://localhost:3000"
    echo
    echo -e "${BLUE}Documentation:${NC}"
    echo "- README.md - Project overview and usage"
    echo "- docs/ - Detailed documentation"
    echo "- config/ - Configuration examples"
    echo
}

# Main setup function
main() {
    echo -e "${BLUE}Alert Triage System Setup${NC}"
    echo "=============================="
    echo
    
    # Check prerequisites
    print_status "Checking prerequisites..."
    
    if ! check_python_version; then
        print_error "Python version check failed"
        exit 1
    fi
    
    # Setup steps
    create_venv
    install_dependencies
    create_directories
    setup_config
    setup_pre_commit
    setup_dev_tools
    check_external_deps
    
    # Optional test run
    if [ "${SKIP_TESTS:-false}" != "true" ]; then
        run_tests
    fi
    
    show_next_steps
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --python-version)
            PYTHON_VERSION="$2"
            shift 2
            ;;
        --help)
            echo "Alert Triage System Setup Script"
            echo
            echo "Usage: $0 [options]"
            echo
            echo "Options:"
            echo "  --skip-tests       Skip running initial tests"
            echo "  --python-version   Specify minimum Python version (default: 3.11)"
            echo "  --help            Show this help message"
            echo
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main setup
main