# GitHub Setup Guide

This guide will help you push this project to GitHub.

## Prerequisites

- A GitHub account (create one at https://github.com)
- Git installed and configured
- SSH key added to GitHub (recommended) or HTTPS credentials

## Step 1: Create a New Repository on GitHub

1. Go to https://github.com/new
2. Fill in the repository details:
   - **Repository name**: `ghidra-mcp-headless` (or your preferred name)
   - **Description**: `Comprehensive MCP server for Ghidra headless malware analysis`
   - **Visibility**:
     - **Public** (recommended for open source)
     - **Private** (if you prefer to keep it private initially)
   - **DO NOT** initialize with README, .gitignore, or license (we already have these)

3. Click "Create repository"

## Step 2: Configure Git Remote

GitHub will show you commands to push an existing repository. Use these:

### Option A: Using SSH (Recommended)

```bash
cd /home/rinzler/Documents/codeProjects/GhidraMCP_headless

# Add remote
git remote add origin git@github.com:YOUR_USERNAME/ghidra-mcp-headless.git

# Verify remote
git remote -v

# Push to GitHub
git push -u origin main
```

### Option B: Using HTTPS

```bash
cd /home/rinzler/Documents/codeProjects/GhidraMCP_headless

# Add remote
git remote add origin https://github.com/YOUR_USERNAME/ghidra-mcp-headless.git

# Verify remote
git remote -v

# Push to GitHub
git push -u origin main
```

**Note:** Replace `YOUR_USERNAME` with your actual GitHub username.

## Step 3: Verify on GitHub

1. Go to your repository: `https://github.com/YOUR_USERNAME/ghidra-mcp-headless`
2. You should see:
   - All your files
   - Nice README with badges
   - GitHub Actions workflow
   - Issue templates
   - Security policy

## Step 4: Configure Repository Settings

### Enable GitHub Actions

1. Go to repository Settings > Actions > General
2. Ensure "Allow all actions and reusable workflows" is selected
3. Click "Save"

### Set Up Branch Protection (Optional but Recommended)

1. Go to Settings > Branches
2. Click "Add rule"
3. Branch name pattern: `main`
4. Enable:
   - [x] Require a pull request before merging
   - [x] Require status checks to pass before merging
   - [x] Require branches to be up to date before merging
5. Click "Create" or "Save changes"

### Add Topics (Tags)

1. Go to your repository main page
2. Click the gear icon next to "About"
3. Add topics:
   - `ghidra`
   - `malware-analysis`
   - `reverse-engineering`
   - `security-research`
   - `mcp-server`
   - `claude-ai`
   - `binary-analysis`
   - `python`
4. Click "Save changes"

### Update Repository Description

In the same "About" section:
- Description: "Comprehensive MCP server providing Claude with advanced malware analysis via Ghidra headless mode"
- Website: (optional - your docs site if you have one)
- Topics: (already added above)

## Step 5: Update Badge URLs in README

Edit `README.md` and replace the badge URLs:

```markdown
[![CI](https://github.com/YOUR_USERNAME/ghidra-mcp-headless/workflows/CI/badge.svg)](https://github.com/YOUR_USERNAME/ghidra-mcp-headless/actions)
```

Replace `YOUR_USERNAME` with your actual GitHub username.

Commit and push:
```bash
git add README.md
git commit -m "docs: Update badge URLs with actual repository"
git push
```

## Step 6: First Actions Run

1. Go to Actions tab on GitHub
2. You should see the CI workflow running automatically
3. Monitor the build to ensure everything passes

## Step 7: Create First Release (Optional)

1. Go to Releases > "Create a new release"
2. Click "Choose a tag" and type `v0.1.0`
3. Release title: `v0.1.0 - Initial Release`
4. Description: Copy from the commit message or create a detailed changelog
5. Click "Publish release"

## Step 8: Enable Security Features

### Enable Dependabot

1. Go to Settings > Security > Code security and analysis
2. Enable:
   - [x] Dependency graph
   - [x] Dependabot alerts
   - [x] Dependabot security updates

### Enable Code Scanning (Optional)

1. Go to Security > Code scanning
2. Set up CodeQL analysis
3. Commit the workflow file

## Next Steps

### Share Your Project

1. **Social Media**: Share on Twitter, LinkedIn, Reddit (r/ReverseEngineering)
2. **Community**: Post to security research communities
3. **Documentation**: Consider creating a GitHub Pages site

### Maintenance

```bash
# Keep your local repo in sync
git pull origin main

# Create feature branches
git checkout -b feature/new-tool
git add .
git commit -m "feat: Add new analysis tool"
git push origin feature/new-tool

# Then create PR on GitHub
```

### Collaboration

- Watch for Issues and PRs
- Set up email notifications
- Review contributions regularly
- Engage with the community

## Troubleshooting

### Authentication Issues

**SSH key not set up:**
```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "your_email@example.com"

# Add to SSH agent
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# Copy public key
cat ~/.ssh/id_ed25519.pub
# Add this to GitHub: Settings > SSH and GPG keys > New SSH key
```

**HTTPS credentials:**
```bash
# Use GitHub CLI for easier authentication
gh auth login

# Or configure git credential helper
git config --global credential.helper cache
```

### Push Rejected

```bash
# If remote has changes you don't have locally
git pull --rebase origin main
git push origin main
```

### Large Files

If you accidentally committed large files:
```bash
# Remove from tracking but keep locally
git rm --cached path/to/large/file
echo "path/to/large/file" >> .gitignore
git commit -m "Remove large file from tracking"
git push
```

## Repository Structure on GitHub

Your repository will look like this:

```
github.com/YOUR_USERNAME/ghidra-mcp-headless/
├── .github/
│   ├── workflows/ci.yml          [Visible in Actions tab]
│   ├── ISSUE_TEMPLATE/           [Auto-loaded for new issues]
│   └── PULL_REQUEST_TEMPLATE.md  [Auto-loaded for new PRs]
├── src/
├── tests/
├── config/
├── samples/
├── README.md                     [Main page]
├── LICENSE                       [Shows license badge]
├── CONTRIBUTING.md               [Linked from README]
├── CODE_OF_CONDUCT.md            [Community standards]
├── SECURITY.md                   [Security tab]
└── ...
```

## GitHub Features You Now Have

- **README**: Professional landing page with badges
- **Actions**: CI/CD pipeline running tests on push
- **Issues**: Bug reports and feature requests with templates
- **Pull Requests**: Contribution workflow with template
- **Security**: Security policy and vulnerability reporting
- **Discussions**: (Enable in Settings if you want community forums)
- **Projects**: (Can create project boards for task management)
- **Wiki**: (Can enable for additional documentation)

## Making Your First Release

After everything is set up and verified:

```bash
# Tag the release
git tag -a v0.1.0 -m "Initial release v0.1.0"
git push origin v0.1.0
```

Then create the release on GitHub using the tag.

## Done!

Your project is now GitHub-ready and publicly available (if you chose public visibility).

**Repository URL**: `https://github.com/YOUR_USERNAME/ghidra-mcp-headless`

Share it with the community and start accepting contributions!

---

**Need Help?**
- GitHub Docs: https://docs.github.com
- Git Reference: https://git-scm.com/docs
- GitHub Community: https://github.community
