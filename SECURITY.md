# Security Policy

## Supported Versions

Currently supported versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Scope

This tool is designed for **defensive security research** and **malware analysis** only.

### What This Tool Does

- **Static analysis only** - Reads binary files without execution
- **Local processing** - All data stays on your machine
- **No network communication** - Purely offline analysis
- **Sandboxed execution** - Ghidra runs in separate JVM process

### What This Tool Does NOT Do

- Execute malware samples
- Connect to C2 servers or networks
- Perform dynamic analysis
- Upload binaries or data anywhere

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow these steps:

### DO NOT

- Create a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before it's been addressed
- Test the vulnerability on systems you don't own or have permission to test

### DO

**Report privately via GitHub Security Advisories:**

1. Go to the repository's Security tab
2. Click "Report a vulnerability"
3. Fill out the security advisory form

**Or email directly to:** security@[project-maintainer-email]

### What to Include

Please include as much information as possible:

- **Description**: Clear description of the vulnerability
- **Impact**: What could an attacker potentially do?
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Proof of Concept**: Code or commands demonstrating the vulnerability (if applicable)
- **Suggested Fix**: If you have ideas for fixing it (optional)
- **Environment**: OS, Python version, Ghidra version, etc.

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Status Updates**: Every 2 weeks until resolved
- **Resolution**: We aim to resolve critical issues within 30 days

### Disclosure Policy

- We follow **coordinated disclosure**
- Security issues will be disclosed after:
  - A fix is released
  - 90 days have passed (whichever comes first)
- You will be credited in the security advisory (unless you prefer anonymity)

## Security Best Practices for Users

### When Analyzing Malware

1. **Always use isolated environments**
   - Virtual machines (VMware, VirtualBox, QEMU)
   - Sandboxed containers (Docker, Podman)
   - Air-gapped systems

2. **Never analyze malware on production systems**
   - Use dedicated analysis machines
   - Take VM snapshots before analysis
   - Restore from clean snapshots after analysis

3. **Verify binary authenticity**
   - Only analyze samples from trusted sources
   - Verify hashes against known malware databases
   - Get proper authorization before analyzing

4. **Protect sensitive data**
   - Don't analyze binaries containing your credentials
   - Be aware that strings/memory may contain sensitive data
   - Clear cache regularly: `rm -rf ~/.ghidra_mcp_cache/`

### System Hardening

1. **Keep software updated**
   ```bash
   # Update Ghidra
   # Update Python: pip install --upgrade pip
   # Update dependencies: uv sync
   ```

2. **Use least privilege**
   - Don't run as root/administrator
   - Use standard user accounts
   - Apply filesystem permissions

3. **Monitor resource usage**
   - Set analysis timeouts
   - Monitor memory usage
   - Watch for unexpected behavior

### Input Validation

The tool validates inputs, but you should also:

- Verify file paths before analysis
- Check binary sizes (avoid excessively large files)
- Scan binaries with antivirus first
- Review strings and metadata before deep analysis

## Known Security Considerations

### 1. Ghidra Vulnerabilities

Ghidra is third-party software. Security issues in Ghidra could affect this tool.

**Mitigation:**
- Keep Ghidra updated to latest stable version
- Monitor Ghidra security advisories
- Use Ghidra in isolated environments

### 2. Malformed Binaries

Malicious binaries may be crafted to exploit analysis tools.

**Mitigation:**
- Analysis runs in separate JVM process
- Timeouts prevent infinite loops
- Error handling prevents crashes
- Sandboxing recommended

### 3. Information Disclosure

Analysis results may contain sensitive information from binaries.

**Mitigation:**
- Cache is local only (~/.ghidra_mcp_cache/)
- No network transmission
- User responsible for protecting analysis results
- Clear cache when done: `make clean`

### 4. Resource Exhaustion

Large or complex binaries may consume significant resources.

**Mitigation:**
- Default 600s timeout
- Memory limits via JVM settings
- Monitor system resources
- Kill runaway processes if needed

## Security Features

### Current Protections

- [x] Input validation on file paths
- [x] Timeout protection for long analyses
- [x] Process isolation (separate JVM)
- [x] No code execution (static analysis only)
- [x] Local-only processing
- [x] Error handling and logging
- [x] SHA256 verification for cache

### Planned Enhancements

- [ ] Additional file type validation
- [ ] Binary size limits (configurable)
- [ ] Enhanced sandboxing options
- [ ] Resource usage monitoring
- [ ] Automated security scanning in CI/CD

## Responsible Disclosure

If you use this tool to discover vulnerabilities in other software:

1. **Follow responsible disclosure practices**
2. **Report to the affected vendor first**
3. **Allow reasonable time for fixes** (typically 90 days)
4. **Don't exploit vulnerabilities maliciously**
5. **Document your findings professionally**

## Compliance

Users are responsible for ensuring their use complies with:

- Local laws and regulations
- Organizational security policies
- Software license agreements
- Ethical hacking guidelines
- Professional codes of conduct

## Security Resources

- **Ghidra Security**: https://github.com/NationalSecurityAgency/ghidra/security
- **Python Security**: https://python.org/dev/security/
- **OWASP**: https://owasp.org/
- **SANS Resources**: https://sans.org/

## Contact

For security issues: Use GitHub Security Advisories or email security@[your-domain]

For general questions: Open a regular GitHub issue

---

**Last Updated:** 2025-10-30
**Version:** 1.0
