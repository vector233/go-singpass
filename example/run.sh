#!/bin/bash

# Go Singpass Example Startup Script

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
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

print_info "Go Singpass Example Application Startup Script"
echo

# Check environment variables
if [ -z "$SINGPASS_CLIENT_ID" ]; then
    print_warning "SINGPASS_CLIENT_ID environment variable not set"
    echo "Please set your Singpass Client ID:"
    echo "export SINGPASS_CLIENT_ID=your_client_id_here"
    echo
    print_info "Or create a .env file:"
    echo "echo 'SINGPASS_CLIENT_ID=your_client_id_here' > .env"
    echo "source .env"
    echo
else
    print_success "SINGPASS_CLIENT_ID is set: ${SINGPASS_CLIENT_ID:0:10}..."
fi

# Check if Redis is running
print_info "Checking Redis service status..."
if ! redis-cli ping > /dev/null 2>&1; then
    print_warning "Redis service is not running"
    print_info "Attempting to start Redis..."
    
    # Try different Redis startup methods
    if command -v brew > /dev/null 2>&1; then
        print_info "Starting Redis with Homebrew..."
        brew services start redis
    elif command -v redis-server > /dev/null 2>&1; then
        print_info "Starting Redis server..."
        redis-server --daemonize yes
    else
        print_error "Redis not found, please install Redis first:"
        echo "macOS: brew install redis"
        echo "Ubuntu: sudo apt-get install redis-server"
        echo "CentOS: sudo yum install redis"
        exit 1
    fi
    
    # Wait for Redis to start
    sleep 2
    
    if redis-cli ping > /dev/null 2>&1; then
        print_success "Redis started successfully"
    else
        print_error "Failed to start Redis, please start Redis service manually"
        exit 1
    fi
else
    print_success "Redis service is running"
fi

# Check Go modules
print_info "Checking Go module dependencies..."
if [ ! -f "go.mod" ]; then
    print_info "Initializing Go modules..."
    go mod init singpass-example
fi

print_info "Downloading dependencies..."
go mod tidy

# Build and run application
print_info "Building application..."
go build -o singpass-example .

print_success "Starting Singpass example application..."
echo
print_info "Application will start at http://localhost:8080"
print_info "Please visit http://localhost:8080 in your browser to start testing"
echo
print_warning "Note: Make sure you have a valid Singpass Client ID for testing"
echo

./singpass-example