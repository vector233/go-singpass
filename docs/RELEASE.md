# Release Guide

This document describes how to create and publish new versions for the Go Singpass project.

## 🚀 Automated Release Process

The project is configured with GitHub Actions automated release process. When pushing semantic version tags, it will automatically:

1. Build multi-platform binary files
2. Generate checksum files
3. Create GitHub Release
4. Upload build artifacts
5. Generate changelog

## 📋 Pre-release Checklist

Before creating a release, ensure:

- [ ] All tests pass
- [ ] Code passes linting checks
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated (optional)
- [ ] Version number follows [Semantic Versioning](https://semver.org/) specification

## 🛠️ Creating a Release

### Method 1: Using Release Script (Recommended)

The project provides a convenient release script:

```bash
# Create stable release
./scripts/release.sh 1.0.0

# Create pre-release
./scripts/release.sh 1.0.0-beta.1
./scripts/release.sh 2.0.0-rc.1
```

The script will automatically:
- Validate version number format
- Check working directory status
- Run tests and code checks
- Create and push tag

### Method 2: Manual Creation

If you prefer manual operation:

```bash
# 1. Ensure on main branch and working directory is clean
git checkout main
git pull origin main
git status

# 2. Run tests
go test ./...

# 3. Run code checks
golangci-lint run

# 4. Create tag
git tag -a v1.0.0 -m "Release v1.0.0"

# 5. Push tag
git push origin v1.0.0
```

## 📦 Build Artifacts

GitHub Actions will automatically build binary files for the following platforms:

- **Linux AMD64**: `go-singpass-linux-amd64`
- **Linux ARM64**: `go-singpass-linux-arm64`
- **macOS AMD64**: `go-singpass-darwin-amd64`
- **macOS ARM64**: `go-singpass-darwin-arm64`
- **Windows AMD64**: `go-singpass-windows-amd64.exe`
- **Checksums**: `checksums.txt`

## 🏷️ Version Number Specification

The project follows [Semantic Versioning](https://semver.org/) specification:

- **Major version**: Incompatible API changes
- **Minor version**: Backward-compatible functionality additions
- **Patch version**: Backward-compatible bug fixes

### Version Number Examples

- `1.0.0` - Stable release
- `1.1.0` - Feature release
- `1.0.1` - Bug fix release
- `2.0.0-beta.1` - Pre-release
- `2.0.0-rc.1` - Release candidate

## 🔄 Release Workflow

### Trigger Conditions

The release workflow triggers when:
- Pushing tags matching `v*.*.*` pattern
- Examples: `v1.0.0`, `v2.1.3`, `v1.0.0-beta.1`

### Workflow Steps

1. **Code Checkout**: Fetch complete git history
2. **Environment Setup**: Install Go 1.21
3. **Build Binaries**: Build executables for multiple platforms
4. **Generate Checksums**: Create SHA256 checksum files
5. **Generate Changelog**: Based on git commit history
6. **Create Release**: Create release on GitHub
7. **Upload Artifacts**: Upload all build files
8. **Update Module Proxy**: Notify Go module proxy to update

## 📝 Changelog

The system will automatically generate changelog including:
- Version information
- Commit records since last version
- Build artifact list

You can also manually edit the description on the GitHub Release page.

## 🔍 Monitoring and Verification

After creating a release, please check:

1. **GitHub Actions**: Confirm workflow completed successfully
   - Visit: https://github.com/vector233/go-singpass/actions

2. **Release Page**: Confirm release has been created
   - Visit: https://github.com/vector233/go-singpass/releases

3. **Go Module**: Confirm new version is available
   ```bash
   go list -m -versions github.com/vector233/go-singpass
   ```

## ❌ Rolling Back a Release

If you need to rollback a release:

1. **Delete GitHub Release**:
   - Delete the corresponding release on GitHub Release page

2. **Delete tag**:
   ```bash
   # Delete local tag
   git tag -d v1.0.0
   
   # Delete remote tag
   git push origin :refs/tags/v1.0.0
   ```

## 🆘 Troubleshooting

### Common Issues

**Q: What if GitHub Actions fails?**
A: Check Actions logs, common causes include:
- Build failures
- Permission issues
- Network issues

**Q: Release not automatically created?**
A: Confirm:
- Tag format is correct (v-prefixed semantic version)
- GitHub Actions has sufficient permissions
- Workflow file syntax is correct

**Q: Binary file build fails?**
A: Check:
- Go code can cross-compile for target platforms
- Dependencies support target platforms
- Build scripts are correct

## 📞 Getting Help

If you encounter issues, you can:
1. Check GitHub Actions logs
2. Review project Issues
3. Contact project maintainers