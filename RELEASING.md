# Release Process

This document describes how to create new releases of the Binary MCP Server.

## Overview

Releases are automated via GitHub Actions. When you push a version tag, the workflow:

1. Builds x64dbg MCP plugins (both x64 and x32)
2. Creates a GitHub release
3. Attaches pre-built plugin binaries
4. Generates release notes

## Creating a Release

### 1. Update Version Numbers

Update version in relevant files:

```bash
# pyproject.toml
version = "0.2.0"

# src/engines/dynamic/x64dbg/plugin/CMakeLists.txt
project(x64dbg_mcp_plugin VERSION 0.2.0 LANGUAGES CXX)
```

### 2. Update Changelog

Add release notes to `README.md` or `CHANGELOG.md`:

```markdown
## v0.2.0 (2025-01-XX)

### Added
- Feature 1
- Feature 2

### Fixed
- Bug 1
- Bug 2

### Changed
- Change 1
```

### 3. Commit Changes

```bash
git add pyproject.toml src/engines/dynamic/x64dbg/plugin/CMakeLists.txt README.md
git commit -m "chore: Bump version to 0.2.0"
git push
```

### 4. Create and Push Tag

```bash
# Create annotated tag
git tag -a v0.2.0 -m "Release v0.2.0"

# Push tag to trigger workflow
git push origin v0.2.0
```

### 5. Monitor Workflow

1. Go to: https://github.com/Sarks0/binary-mcp/actions
2. Watch the "Build and Release" workflow
3. Wait for completion (~5-10 minutes)

### 6. Verify Release

1. Go to: https://github.com/Sarks0/binary-mcp/releases
2. Check that release v0.2.0 was created
3. Verify attached assets:
   - `x64dbg_mcp.dp64` (64-bit plugin)
   - `x64dbg_mcp.dp32` (32-bit plugin)
   - `README.md` (plugin installation guide)

### 7. Test Installation

Test the installer downloads plugins correctly:

```powershell
# Windows
Remove-Item -Recurse -Force $env:USERPROFILE\binary-mcp
Remove-Item -Recurse -Force $env:USERPROFILE\x64dbg
.\install.ps1
```

Check that plugins are installed:
```powershell
dir $env:USERPROFILE\x64dbg\release\x64\plugins\x64dbg_mcp.dp64
dir $env:USERPROFILE\x64dbg\release\x32\plugins\x64dbg_mcp.dp32
```

## Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR.MINOR.PATCH** (e.g., 1.2.3)
  - **MAJOR**: Breaking changes
  - **MINOR**: New features (backward compatible)
  - **PATCH**: Bug fixes (backward compatible)

Examples:
- `v0.1.0` - Initial release
- `v0.2.0` - Added dynamic analysis features
- `v0.2.1` - Fixed x64dbg connection bug
- `v1.0.0` - First stable release

## Pre-releases

For testing, create pre-release versions:

```bash
git tag -a v0.2.0-beta.1 -m "Release v0.2.0-beta.1"
git push origin v0.2.0-beta.1
```

Mark as pre-release in GitHub:
1. Edit release
2. Check "This is a pre-release"

## Hotfix Releases

For urgent fixes:

```bash
# Create hotfix branch from tag
git checkout -b hotfix-0.2.1 v0.2.0

# Make fixes
git commit -m "fix: Critical bug in x64dbg bridge"

# Merge to main
git checkout main
git merge hotfix-0.2.1

# Tag and push
git tag -a v0.2.1 -m "Hotfix v0.2.1"
git push origin main v0.2.1
```

## Workflow Details

### Build Steps

The workflow (`.github/workflows/release.yml`) performs:

1. **Setup**: Windows runner with Visual Studio and CMake
2. **SDK Download**: Fetches x64dbg SDK from GitHub
3. **Build x64**: Compiles 64-bit plugin (`x64dbg_mcp.dp64`)
4. **Build x32**: Compiles 32-bit plugin (`x64dbg_mcp.dp32`)
5. **Package**: Creates release artifacts
6. **Release**: Creates GitHub release with assets

### Build Requirements

The workflow requires:
- Windows runner (windows-latest)
- Visual Studio 2022
- CMake 3.27+
- x64dbg SDK (auto-downloaded)

### Troubleshooting

**Build fails:**
- Check GitHub Actions logs
- Verify CMakeLists.txt is correct
- Ensure plugin source files compile

**Plugin not found by installer:**
- Check release assets include both .dp64 and .dp32
- Verify asset names match exactly: `x64dbg_mcp.dp64`, `x64dbg_mcp.dp32`
- Check installer script fetches from correct repo

**SDK download fails:**
- x64dbg repository may be unavailable
- Workflow can be updated to cache SDK

## Manual Release (Fallback)

If automated workflow fails, create release manually:

### 1. Build Plugins Locally

```bash
# Windows with Visual Studio 2022
cd src/engines/dynamic/x64dbg/plugin

# Build x64
mkdir build-x64 && cd build-x64
cmake .. -G "Visual Studio 17 2022" -A x64 -DX64DBG_SDK_PATH="path/to/sdk"
cmake --build . --config Release

# Build x32
cd ..
mkdir build-x32 && cd build-x32
cmake .. -G "Visual Studio 17 2022" -A Win32 -DX64DBG_SDK_PATH="path/to/sdk"
cmake --build . --config Release
```

### 2. Create Release on GitHub

1. Go to: https://github.com/Sarks0/binary-mcp/releases/new
2. Choose tag: Create new tag `v0.2.0`
3. Release title: `Release v0.2.0`
4. Add description (see workflow for template)
5. Upload files:
   - `build-x64/Release/x64dbg_mcp.dp64`
   - `build-x32/Release/x64dbg_mcp.dp32`
6. Publish release

## Post-Release Tasks

After successful release:

1. **Announce**: Update README badges, social media, etc.
2. **Monitor**: Watch for user issues with new release
3. **Document**: Update wiki/docs with new features
4. **PyPI**: (Future) Publish Python package to PyPI

## Release Checklist

- [ ] Update version numbers in all files
- [ ] Update changelog/release notes
- [ ] Commit and push changes
- [ ] Create and push annotated tag
- [ ] Verify workflow completes successfully
- [ ] Test installer downloads plugins
- [ ] Test plugins work in x64dbg
- [ ] Announce release

## Future Improvements

- [ ] Add PyPI publishing to workflow
- [ ] Generate changelog automatically from commits
- [ ] Add release notification (Discord, Slack, etc.)
- [ ] Cache x64dbg SDK in workflow for faster builds
- [ ] Add plugin signature verification
- [ ] Create Docker images for releases
