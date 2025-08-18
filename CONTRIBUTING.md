# Contributing to Go Singpass

We welcome contributions to the Go Singpass library! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Go 1.21 or later
- Redis server (for testing)
- Git

### Setting up the Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/go-singpass.git
   cd go-singpass
   ```

3. Install dependencies:
   ```bash
   go mod tidy
   ```

4. Start Redis for testing:
   ```bash
   redis-server
   ```

5. Run tests to ensure everything works:
   ```bash
   go test -v
   ```

## Development Guidelines

### Code Style

- Follow standard Go formatting using `gofmt`
- Use `golint` and `go vet` to check code quality
- Write clear, self-documenting code with appropriate comments
- Follow Go naming conventions

### Testing

- Write tests for all new functionality
- Maintain or improve test coverage
- Use table-driven tests where appropriate
- Include both unit tests and integration tests
- Mock external dependencies when necessary

### Documentation

- Update documentation for any API changes
- Include code examples in documentation
- Write clear commit messages
- Update CHANGELOG.md for significant changes

## Types of Contributions

### Bug Reports

When reporting bugs, please include:

- Go version
- Library version
- Minimal code example that reproduces the issue
- Expected vs actual behavior
- Error messages and stack traces
- Environment details (OS, Redis version, etc.)

### Feature Requests

For new features:

- Describe the use case and motivation
- Provide examples of how the feature would be used
- Consider backward compatibility
- Discuss the implementation approach

### Code Contributions

1. **Create an Issue**: For significant changes, create an issue first to discuss the approach

2. **Create a Branch**: Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Changes**: Implement your changes following the guidelines above

4. **Write Tests**: Add comprehensive tests for your changes

5. **Update Documentation**: Update relevant documentation

6. **Run Tests**: Ensure all tests pass:
   ```bash
   go test -v
   go test -race -v
   ```

7. **Check Code Quality**:
   ```bash
   gofmt -s -w .
   go vet ./...
   golint ./...
   ```

8. **Commit Changes**: Write clear commit messages:
   ```bash
   git commit -m "feat: add support for custom JWKS cache TTL"
   ```

9. **Push and Create PR**: Push your branch and create a pull request

## Pull Request Process

1. **PR Title**: Use conventional commit format (feat:, fix:, docs:, etc.)

2. **Description**: Provide a clear description of:
   - What changes were made
   - Why the changes were necessary
   - How to test the changes
   - Any breaking changes

3. **Checklist**: Ensure your PR includes:
   - [ ] Tests for new functionality
   - [ ] Documentation updates
   - [ ] No breaking changes (or clearly documented)
   - [ ] All tests pass
   - [ ] Code follows style guidelines

4. **Review Process**: 
   - Maintainers will review your PR
   - Address any feedback or requested changes
   - Once approved, your PR will be merged

## Commit Message Guidelines

Use conventional commit format:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

Examples:
```
feat: add support for custom Redis configuration
fix: handle edge case in token validation
docs: update API documentation for new methods
test: add integration tests for callback handling
```

## Security

For security-related issues:

1. **Do not** create public issues for security vulnerabilities
2. Email security concerns to [security@example.com]
3. Include detailed information about the vulnerability
4. Allow time for the issue to be addressed before public disclosure

## Code of Conduct

### Our Pledge

We are committed to making participation in this project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment include:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

### Unacceptable Behavior

Examples of unacceptable behavior include:

- The use of sexualized language or imagery
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Other conduct which could reasonably be considered inappropriate in a professional setting

## Getting Help

If you need help:

1. Check the [API documentation](docs/API.md)
2. Look at existing issues and discussions
3. Create a new issue with the "question" label
4. Join our community discussions

## Recognition

Contributors will be recognized in:

- CHANGELOG.md for significant contributions
- README.md contributors section
- Release notes for major contributions

Thank you for contributing to Go Singpass!