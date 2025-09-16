# Alert Triage System - Makefile
# Convenient commands for development, testing, and deployment

.PHONY: help install install-dev test test-unit test-integration test-performance \
        format lint type-check security-check clean build docker-build docker-run \
        docker-stop k8s-deploy k8s-delete demo run logs metrics docs \
        setup-dev requirements freeze backup restore

# Default target
help: ## Show this help message
	@echo "Alert Triage System - Available Commands"
	@echo "========================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development Setup
setup-dev: ## Set up development environment
	@echo "Setting up development environment..."
	chmod +x scripts/setup.sh
	./scripts/setup.sh

install: requirements.txt ## Install production dependencies
	@echo "Installing production dependencies..."
	pip install -r requirements.txt

install-dev: requirements-dev.txt ## Install development dependencies
	@echo "Installing development dependencies..."
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	pre-commit install

# Testing
test: ## Run all tests
	@echo "Running all tests..."
	python -m pytest tests/ -v --cov=src/ --cov-report=html --cov-report=term

test-unit: ## Run unit tests only
	@echo "Running unit tests..."
	python -m pytest tests/unit/ -v

test-integration: ## Run integration tests only
	@echo "Running integration tests..."
	python -m pytest tests/integration/ -v

test-performance: ## Run performance tests
	@echo "Running performance tests..."
	python -m pytest tests/performance/ -v --benchmark-only

test-coverage: ## Generate test coverage report
	@echo "Generating coverage report..."
	python -m pytest tests/ --cov=src/ --cov-report=html --cov-report=xml
	@echo "Coverage report generated in htmlcov/"

# Code Quality
format: ## Format code with black and isort
	@echo "Formatting code..."
	black src/ tests/ scripts/
	isort src/ tests/ scripts/

lint: ## Run linting with flake8
	@echo "Running linter..."
	flake8 src/ tests/

type-check: ## Run type checking with mypy
	@echo "Running type checks..."
	mypy src/

security-check: ## Run security checks with bandit
	@echo "Running security checks..."
	bandit -r src/ -f json -o security-report.json
	@echo "Security report generated: security-report.json"

code-quality: format lint type-check security-check ## Run all code quality checks

# Application Commands
demo: ## Run the system in demo mode
	@echo "Starting Alert Triage System in demo mode..."
	python src/main.py demo

run: ## Run the system in production mode
	@echo "Starting Alert Triage System..."
	python src/main.py

run-dev: ## Run the system in development mode
	@echo "Starting Alert Triage System in development mode..."
	ENVIRONMENT=development LOG_LEVEL=DEBUG python src/main.py

# Docker Commands
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t alert-triage:latest -f deployment/docker/Dockerfile .

docker-build-dev: ## Build Docker image for development
	@echo "Building development Docker image..."
	docker build -t alert-triage:dev -f deployment/docker/Dockerfile --target development .

docker-run: ## Run with Docker Compose
	@echo "Starting Alert Triage System with Docker Compose..."
	docker-compose -f deployment/docker/docker-compose.yml up -d

docker-run-prod: ## Run production stack with Docker Compose
	@echo "Starting production stack..."
	docker-compose -f deployment/docker/docker-compose.prod.yml up -d

docker-stop: ## Stop Docker containers
	@echo "Stopping Docker containers..."
	docker-compose -f deployment/docker/docker-compose.yml down

docker-logs: ## View Docker logs
	docker-compose -f deployment/docker/docker-compose.yml logs -f

docker-clean: ## Clean up Docker resources
	@echo "Cleaning up Docker resources..."
	docker-compose -f deployment/docker/docker-compose.yml down -v
	docker system prune -f

# Kubernetes Commands
k8s-deploy: ## Deploy to Kubernetes
	@echo "Deploying to Kubernetes..."
	kubectl apply -f deployment/kubernetes/

k8s-delete: ## Delete from Kubernetes
	@echo "Deleting from Kubernetes..."
	kubectl delete -f deployment/kubernetes/

k8s-status: ## Check Kubernetes deployment status
	@echo "Checking Kubernetes status..."
	kubectl get pods -n alert-triage
	kubectl get services -n alert-triage

k8s-logs: ## View Kubernetes logs
	kubectl logs -n alert-triage -l app=alert-triage -f

k8s-port-forward: ## Port forward for local access
	@echo "Setting up port forwarding..."
	kubectl port-forward -n alert-triage service/alert-triage-service 8080:8080 &
	kubectl port-forward -n alert-triage service/alert-triage-service 8081:8081 &

# Monitoring and Debugging
logs: ## View application logs
	@if [ -f "logs/alert_triage.log" ]; then \
		tail -f logs/alert_triage.log; \
	else \
		echo "Log file not found. Is the application running?"; \
	fi

metrics: ## Open metrics endpoint
	@echo "Opening metrics endpoint..."
	@if command -v open >/dev/null 2>&1; then \
		open http://localhost:9090/metrics; \
	elif command -v xdg-open >/dev/null 2>&1; then \
		xdg-open http://localhost:9090/metrics; \
	else \
		echo "Metrics available at: http://localhost:9090/metrics"; \
	fi

health-check: ## Check system health
	@echo "Checking system health..."
	@curl -s http://localhost:8080/health | python -m json.tool || echo "Health check failed"

# Test Alert Commands
send-test-alert: ## Send a test alert via webhook
	@echo "Sending test alert..."
	@curl -X POST http://localhost:8080/webhook/alert \
		-H "Content-Type: application/json" \
		-d '{ \
			"alert_id": "TEST-'$$(date +%s)'", \
			"timestamp": "'$$(date -u +%Y-%m-%dT%H:%M:%SZ)'", \
			"source_system": "makefile", \
			"type": "brute_force", \
			"description": "Test alert from Makefile", \
			"source_ip": "203.0.113.45", \
			"user_id": "test_user" \
		}' && echo

send-test-alerts: ## Send multiple test alerts
	@echo "Sending multiple test alerts..."
	@for i in {1..5}; do \
		$(MAKE) send-test-alert; \
		sleep 1; \
	done

# Documentation
docs: ## Generate documentation
	@echo "Generating documentation..."
	@if command -v sphinx-build >/dev/null 2>&1; then \
		sphinx-build -b html docs/ docs/_build/html; \
		echo "Documentation generated in docs/_build/html/"; \
	else \
		echo "Sphinx not installed. Install with: pip install sphinx"; \
	fi

docs-serve: ## Serve documentation locally
	@echo "Serving documentation..."
	@if [ -d "docs/_build/html" ]; then \
		python -m http.server 8000 -d docs/_build/html; \
	else \
		echo "Documentation not built. Run 'make docs' first."; \
	fi

# Maintenance
clean: ## Clean up temporary files
	@echo "Cleaning up..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type f -name ".coverage" -delete
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf dist/
	rm -rf build/

clean-logs: ## Clean log files
	@echo "Cleaning log files..."
	rm -rf logs/*.log*

requirements: ## Generate requirements.txt from current environment
	@echo "Generating requirements.txt..."
	pip freeze > requirements.txt

freeze: requirements ## Alias for requirements

# Backup and Restore
backup: ## Create system backup
	@echo "Creating backup..."
	@timestamp=$$(date +%Y%m%d_%H%M%S); \
	backup_dir="backups/backup_$$timestamp"; \
	mkdir -p "$$backup_dir"; \
	cp -r config/ "$$backup_dir/"; \
	cp -r data/ "$$backup_dir/" 2>/dev/null || true; \
	cp -r logs/ "$$backup_dir/" 2>/dev/null || true; \
	echo "Backup created: $$backup_dir"

restore: ## Restore from backup (specify BACKUP_DIR)
	@if [ -z "$(BACKUP_DIR)" ]; then \
		echo "Usage: make restore BACKUP_DIR=backups/backup_YYYYMMDD_HHMMSS"; \
		exit 1; \
	fi
	@echo "Restoring from $(BACKUP_DIR)..."
	@if [ -d "$(BACKUP_DIR)" ]; then \
		cp -r "$(BACKUP_DIR)/config/"* config/ 2>/dev/null || true; \
		cp -r "$(BACKUP_DIR)/data/"* data/ 2>/dev/null || true; \
		echo "Restore completed from $(BACKUP_DIR)"; \
	else \
		echo "Backup directory not found: $(BACKUP_DIR)"; \
		exit 1; \
	fi

# Performance and Load Testing
load-test: ## Run load test against webhook
	@echo "Running load test..."
	@if command -v ab >/dev/null 2>&1; then \
		ab -n 1000 -c 10 -T application/json \
			-p scripts/test_data/sample_alert.json \
			http://localhost:8080/webhook/alert; \
	else \
		echo "Apache Bench (ab) not found. Install apache2-utils package."; \
	fi

stress-test: ## Run stress test
	@echo "Running stress test..."
	python tests/performance/stress_test.py

benchmark: ## Run performance benchmarks
	@echo "Running performance benchmarks..."
	python -m pytest tests/performance/ --benchmark-only --benchmark-sort=mean

# Database Commands (if using database)
db-migrate: ## Run database migrations
	@echo "Running database migrations..."
	# Add your database migration command here
	@echo "Database migrations would run here"

db-seed: ## Seed database with test data
	@echo "Seeding database..."
	# Add your database seeding command here
	@echo "Database seeding would run here"

# Security
audit: ## Run security audit
	@echo "Running security audit..."
	pip-audit
	safety check

update-deps: ## Update dependencies
	@echo "Updating dependencies..."
	pip install --upgrade pip
	pip-compile --upgrade requirements.in
	pip-compile --upgrade requirements-dev.in

# CI/CD
ci: clean install test lint type-check security-check ## Run CI pipeline locally
	@echo "CI pipeline completed successfully!"

# Development Utilities
shell: ## Start Python shell with project context
	@echo "Starting Python shell..."
	python -i -c "import sys; sys.path.append('src'); print('Alert Triage System shell ready')"

notebook: ## Start Jupyter notebook
	@echo "Starting Jupyter notebook..."
	jupyter notebook

# Quick Status Check
status: ## Show system status
	@echo "Alert Triage System Status"
	@echo "=========================="
	@echo "Python version: $$(python --version)"
	@echo "Virtual env: $${VIRTUAL_ENV:-Not activated}"
	@echo "Git branch: $$(git branch --show-current 2>/dev/null || echo 'Not a git repo')"
	@echo "Docker status: $$(docker info >/dev/null 2>&1 && echo 'Running' || echo 'Not running')"
	@echo ""
	@if curl -s http://localhost:8080/health >/dev/null 2>&1; then \
		echo "Service status: Running (http://localhost:8080)"; \
	else \
		echo "Service status: Not running"; \
	fi

# Variables for customization
PYTHON ?= python
PIP ?= pip
PYTEST ?= python -m pytest
DOCKER_COMPOSE ?= docker-compose
KUBECTL ?= kubectl

# Include local makefile for customizations
-include Makefile.local