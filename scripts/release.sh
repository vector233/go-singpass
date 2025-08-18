#!/bin/bash

# Go Singpass Release Script
# Script for creating and pushing release tags

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored messages
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

# Check if version number is provided
if [ $# -eq 0 ]; then
    print_error "Please provide version number"
    echo "Usage: $0 <version>"
    echo "Example: $0 1.0.0"
    echo "         $0 1.0.0-beta.1"
    exit 1
fi

VERSION=$1

# Validate version format (semantic versioning)
if ! [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
    print_error "Invalid version format, please use semantic versioning"
    echo "Correct format: X.Y.Z or X.Y.Z-prerelease"
    echo "Examples: 1.0.0, 2.1.3, 1.0.0-beta.1"
    exit 1
fi

TAG="v$VERSION"

print_info "Preparing to create release: $TAG"

# Check if current branch is main
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    print_warning "Not on main branch (current: $CURRENT_BRANCH)"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Cancelled"
        exit 0
    fi
fi

# Check if working directory is clean
if ! git diff-index --quiet HEAD --; then
    print_error "Working directory is not clean, please commit or stash changes first"
    git status --porcelain
    exit 1
fi

# Check if tag already exists
if git tag -l | grep -q "^$TAG$"; then
    print_error "Tag $TAG already exists"
    exit 1
fi

# Pull latest code
print_info "Pulling latest code..."
git pull origin main

# Run tests
print_info "Running tests..."
if ! go test -v ./...; then
    print_error "Tests failed, please fix before creating release"
    exit 1
fi

# Run linting
print_info "Running code checks..."
if command -v golangci-lint &> /dev/null; then
    if ! golangci-lint run; then
        print_error "Code checks failed, please fix before creating release"
        exit 1
    fi
else
    print_warning "golangci-lint not installed, skipping code checks"
fi

# Confirm release creation
print_info "About to create and push tag: $TAG"
read -p "Confirm to continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "Cancelled"
    exit 0
fi

# Create tag
print_info "Creating tag: $TAG"
git tag -a "$TAG" -m "Release $TAG"

# Push tag
print_info "Pushing tag to remote repository..."
git push origin "$TAG"

print_success "Tag $TAG has been successfully created and pushed!"
print_info "GitHub Actions will automatically create release, check: https://github.com/vector233/go-singpass/actions"
print_info "Release page: https://github.com/vector233/go-singpass/releases"

# Show next steps
echo
print_info "Next steps:"
echo "1. Check GitHub Actions execution status"
echo "2. Confirm release has been successfully created"
echo "3. Edit release description (optional)"
echo "4. Notify users about new version release"