# SECURITY ASSESSMENT REPORT
## binary-mcp: MCP Server for Binary Analysis

---

## Executive Summary

This comprehensive security assessment of the binary-mcp repository reveals **multiple critical and high-severity vulnerabilities** that pose significant security risks. The project is an MCP (Model Context Protocol) server designed for binary analysis using Ghidra (static analysis) and x64dbg (dynamic debugging).

### Risk Level: **HIGH**

**Critical Findings:**
- Command injection vulnerabilities in installation scripts
- Arbitrary file read/write through path traversal
- Insufficient input validation on user-supplied paths
- Insecure HTTP server in C++ plugin (no authentication)
- Memory safety concerns in C++ plugin
- Insecure default configurations

**Immediate Action Required:**
1. Fix command injection vulnerability in `install.py` (CRITICAL)
2. Implement path sanitization for all file operations (HIGH)
3. Add authentication to x64dbg HTTP server (HIGH)
4. Add input validation for all user-supplied parameters (HIGH)

### Overall Security Posture
- **Attack Surface:** Large (file uploads, subprocess execution, HTTP server, external integrations)
- **Authentication/Authorization:** None implemented
- **Input Validation:** Minimal
- **Output Encoding:** Partial (JSON escaping present)
- **Error Handling:** Present but verbose (information disclosure risk)

---

## Vulnerability Reports

### 1. Command Injection in Installation Script

**Severity:** CRITICAL (CVSS: 9.8)

**Location:** `install.py` line 108

**Description:**
The installation script uses `subprocess.run()` with `shell=True` and unsanitized input, allowing an attacker to inject arbitrary commands through environment manipulation or malicious input.

**Vulnerable Code:**
```python
cmd = "curl -LsSf https://astral.sh/uv/install.sh | sh"
subprocess.run(cmd, shell=True, check=True)
```

**Impact:**
- Remote code execution during installation
- Supply chain attack via malicious install script
- Privilege escalation if run with elevated permissions

**Remediation:**
```python
# SECURE VERSION - Remove shell=True and use proper subprocess handling
import urllib.request
import tempfile

# Download to temporary file first
with tempfile.NamedTemporaryFile(delete=False, suffix='.sh') as tmp:
    req = urllib.request.Request(
        'https://astral.sh/uv/install.sh',
        headers={'User-Agent': 'binary-mcp-installer'}
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        tmp.write(response.read())
    tmp_path = tmp.name

# Verify script signature/hash before execution
# Execute without shell=True
subprocess.run(['sh', tmp_path], check=True, shell=False)
os.unlink(tmp_path)
```

---

### 2. Path Traversal Vulnerabilities

**Severity:** HIGH (CVSS: 8.2)

**Locations:**
- `src/server.py`: Lines 171-233, 256, 315, 374
- `src/engines/static/ghidra/runner.py`: Lines 143-177
- `src/engines/static/ghidra/project_cache.py`: Lines 33-47

**Description:**
User-supplied file paths in `analyze_binary()`, `get_analysis_context()`, and other functions lack proper sanitization, allowing directory traversal attacks using `../` sequences or absolute paths.

**Attack Vector:**
```python
# Attack vector
analyze_binary(
    binary_path="/etc/passwd",  # Read system files
    force_reanalyze=True
)

# Or with path traversal
analyze_binary(
    binary_path="../../../etc/passwd",
    force_reanalyze=True
)
```

**Impact:**
- Read arbitrary files on the system
- Analyze sensitive binaries without authorization
- Cache poisoning
- Symlink attacks

**Remediation:**
```python
from pathlib import Path

def sanitize_binary_path(binary_path: str, allowed_dirs: list[Path]) -> Path:
    """
    Sanitize and validate binary path to prevent path traversal.
    """
    # Convert to absolute path
    path = Path(binary_path).resolve()

    # Check if path exists and is a file
    if not path.exists():
        raise ValueError(f"File does not exist: {path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    # Check if path is within allowed directories
    if allowed_dirs:
        if not any(path.is_relative_to(allowed_dir) for allowed_dir in allowed_dirs):
            raise ValueError(f"Access denied: Path outside allowed directories")

    # Reject symlinks pointing outside allowed dirs
    if path.is_symlink():
        real_path = path.readlink()
        if allowed_dirs and not any(real_path.is_relative_to(d) for d in allowed_dirs):
            raise ValueError("Symlink target outside allowed directories")

    # Check file size (prevent DoS)
    max_size = 500 * 1024 * 1024  # 500MB
    if path.stat().st_size > max_size:
        raise ValueError(f"File too large: {path.stat().st_size} bytes")

    return path
```

---

### 3. Unauthenticated HTTP Server in x64dbg Plugin

**Severity:** HIGH (CVSS: 8.4)

**Location:** `src/engines/dynamic/x64dbg/plugin/http_server.cpp`

**Description:**
The HTTP server in the x64dbg plugin listens on `127.0.0.1:8765` without any authentication or authorization mechanism. Any process on the local machine can send commands to the debugger.

**Vulnerable Code:**
```cpp
void HttpServer::ServerThread(int port) {
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // Bind to localhost (good) but NO AUTHENTICATION
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Accept loop - accepts ALL connections
    while (s_running) {
        SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
        // NO AUTHENTICATION CHECK HERE

        char buffer[8192];
        int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        std::string response = HandleRequest(request);
        send(clientSocket, response.c_str(), (int)response.size(), 0);
    }
}
```

**Impact:**
- Local malware controlling the debugger
- Malicious browser scripts accessing the HTTP API
- Unauthorized breakpoint manipulation
- Information disclosure through memory dumps

**Remediation:**
```cpp
// Add authentication token
class HttpServer {
private:
    static std::string s_auth_token;

public:
    static bool Initialize(int port) {
        // Generate random auth token on startup
        s_auth_token = GenerateSecureToken();
        SaveTokenToFile(s_auth_token);
        ...
    }

    static std::string HandleRequest(const std::string& request) {
        // Extract Authorization header
        std::string auth_header = ExtractHeader(request, "Authorization");

        // Validate token
        if (auth_header != "Bearer " + s_auth_token) {
            return "HTTP/1.1 401 Unauthorized\r\n"
                   "WWW-Authenticate: Bearer\r\n\r\n"
                   "{\"error\":\"Invalid or missing authentication token\"}";
        }

        // Continue with normal request handling
        ...
    }
};
```

---

### 4. Buffer Overflow Risk in HTTP Request Handler

**Severity:** MEDIUM (CVSS: 6.5)

**Location:** `src/engines/dynamic/x64dbg/plugin/http_server.cpp` lines 93-96

**Description:**
Fixed-size buffer (8192 bytes) for receiving HTTP requests without proper size validation, potentially leading to buffer overflow.

**Vulnerable Code:**
```cpp
char buffer[8192];
int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
if (received > 0) {
    buffer[received] = '\0';  // Null terminator
    std::string request(buffer);
```

**Remediation:**
```cpp
std::string HttpServer::ReceiveRequest(SOCKET clientSocket) {
    const size_t MAX_REQUEST_SIZE = 1024 * 1024;  // 1MB limit
    const size_t CHUNK_SIZE = 8192;

    std::string request;
    request.reserve(CHUNK_SIZE);

    char buffer[CHUNK_SIZE];
    size_t total_received = 0;

    while (total_received < MAX_REQUEST_SIZE) {
        int received = recv(clientSocket, buffer, sizeof(buffer), 0);

        if (received <= 0) break;

        if (total_received + received > MAX_REQUEST_SIZE) {
            throw std::runtime_error("Request exceeds maximum size");
        }

        request.append(buffer, received);
        total_received += received;

        if (IsCompleteHttpRequest(request)) break;
    }

    return request;
}
```

---

### 5. Insecure JSON Parsing

**Severity:** MEDIUM (CVSS: 5.9)

**Location:** `src/engines/dynamic/x64dbg/plugin/http_server.cpp` lines 171-175

**Description:**
JSON request bodies are parsed without validation, potentially allowing malformed JSON to cause crashes.

**Vulnerable Code:**
```cpp
std::string HttpServer::ParseJsonBody(const std::string& request) {
    size_t bodyStart = request.find("\r\n\r\n");
    if (bodyStart == std::string::npos) return "{}";
    return request.substr(bodyStart + 4);  // No validation
}
```

**Remediation:**
```cpp
#include <nlohmann/json.hpp>

std::string HttpServer::ParseAndValidateJsonBody(const std::string& request) {
    size_t bodyStart = request.find("\r\n\r\n");
    if (bodyStart == std::string::npos) return "{}";

    std::string body = request.substr(bodyStart + 4);

    const size_t MAX_BODY_SIZE = 10 * 1024 * 1024;  // 10MB
    if (body.size() > MAX_BODY_SIZE) {
        throw std::runtime_error("Request body too large");
    }

    try {
        nlohmann::json parsed = nlohmann::json::parse(body);
        if (parsed.size() > 100) {
            throw std::runtime_error("Too many JSON fields");
        }
        return parsed.dump();
    }
    catch (const nlohmann::json::exception& e) {
        throw std::runtime_error("Invalid JSON in request body");
    }
}
```

---

### 6. Environment Variable Injection

**Severity:** MEDIUM (CVSS: 6.3)

**Location:** `src/engines/static/ghidra/runner.py` lines 189-191

**Description:**
Environment variables used to pass data between processes without validation.

**Vulnerable Code:**
```python
env = os.environ.copy()
env["GHIDRA_CONTEXT_JSON"] = str(output_path)
```

**Remediation:**
```python
def sanitize_output_path(output_path: Path, allowed_dir: Path) -> Path:
    """Sanitize output path to prevent directory traversal."""
    abs_path = output_path.resolve()
    abs_allowed = allowed_dir.resolve()

    if not abs_path.is_relative_to(abs_allowed):
        raise ValueError(f"Output path must be within {abs_allowed}")

    if not abs_path.parent.exists():
        raise ValueError("Parent directory does not exist")

    for parent in abs_path.parents:
        if parent == abs_allowed:
            break
        if parent.is_symlink():
            raise ValueError("Symlinks not allowed in output path")

    return abs_path
```

---

### 7. Information Disclosure through Verbose Error Messages

**Severity:** LOW (CVSS: 3.7)

**Description:**
Detailed error messages expose internal system information including file paths, stack traces, and configuration details throughout the codebase.

**Example:**
```python
if not output_path.exists():
    error_msg = f"Ghidra did not create output file: {output_path}\n"
    error_msg += f"Check debug log at: {debug_file}\n\n"
    error_msg += f"Ghidra stdout (last 500 chars):\n{result.get('stdout', 'N/A')[-500:]}\n\n"
    error_msg += f"Ghidra stderr:\n{result.get('stderr', 'N/A')[-500:]}"
    raise RuntimeError(error_msg)
```

**Remediation:**
```python
class UserFacingError(Exception):
    def __init__(self, user_message: str, internal_details: str = None):
        super().__init__(user_message)
        self.user_message = user_message
        self.internal_details = internal_details
        self.error_id = str(uuid.uuid4())[:8]

        if internal_details:
            logger.error(f"Error {self.error_id}: {internal_details}")

@safe_error_handler
def analyze_binary(binary_path: str, ...) -> str:
    try:
        context = get_analysis_context(binary_path, ...)
        return summary
    except FileNotFoundError as e:
        raise UserFacingError(
            "Binary file not found. Please verify the file path.",
            internal_details=f"File not found: {binary_path}, {str(e)}"
        )
```

---

### 8. Insecure Temporary File Handling

**Severity:** MEDIUM (CVSS: 5.5)

**Location:** `install.py` lines 155, 242

**Description:**
Temporary files created with predictable names in shared directories, potentially allowing symlink attacks.

**Vulnerable Code:**
```python
temp_zip = Path("/tmp") / "ghidra.zip"
download_file(asset["browser_download_url"], temp_zip, f"Ghidra {version}")
```

**Remediation:**
```python
import tempfile

def secure_temp_file(prefix: str, suffix: str) -> Path:
    fd, temp_path = tempfile.mkstemp(
        prefix=f"{prefix}_",
        suffix=suffix,
        dir=None
    )
    os.close(fd)
    os.chmod(temp_path, 0o600)  # Owner read/write only
    return Path(temp_path)

# Usage:
temp_zip = secure_temp_file("ghidra_download", ".zip")
try:
    download_file(asset["browser_download_url"], temp_zip, f"Ghidra {version}")
    # ... process file
finally:
    temp_zip.unlink(missing_ok=True)
```

---

## Additional Vulnerabilities

### 9. Missing Input Validation on Numeric Parameters (MEDIUM)

**Locations:**
- `get_functions(..., limit: int = 100)` - No max limit check
- `get_strings(..., min_length: int = 4, limit: int = 100)` - No bounds checking
- `x64dbg_read_memory(..., size: int = 256)` - No maximum size limit

**Risk:** Resource exhaustion, denial of service

### 10. Regex Denial of Service (ReDoS) (MEDIUM)

**Location:** `src/server.py` lines 264, 325, 382

User-supplied regex patterns without timeout or complexity validation could cause catastrophic backtracking.

### 11. Race Condition in Cache Management (LOW)

**Location:** `src/engines/static/ghidra/project_cache.py`

Concurrent access to cache files may lead to corruption.

### 12. Missing JSON Escaping in C++ (LOW)

**Location:** `src/engines/dynamic/x64dbg/plugin/commands.cpp`

```cpp
static std::string String(const std::string& value) {
    return "\"" + value + "\"";  // No escaping!
}
```

---

## Attack Scenarios

### Scenario 1: Local Privilege Escalation via Path Traversal

1. Attacker exploits path traversal in `analyze_binary()` to read `/etc/shadow`
2. Content is cached in `~/.ghidra_mcp_cache/` with world-readable permissions
3. Attacker reads cached file containing password hashes
4. Cracks passwords offline
5. Escalates to root using cracked credentials

**Impact:** Complete system compromise

### Scenario 2: Remote Code Execution via Installation Script

1. Attacker performs MITM attack on network
2. Victim runs `install.py`
3. Attacker intercepts and replaces install script
4. `subprocess.run(cmd, shell=True)` executes malicious script
5. Attacker gains code execution with victim's privileges

**Impact:** Complete system compromise, persistent access

### Scenario 3: Debugger Hijacking via Unauthenticated HTTP API

1. Victim loads malware sample in x64dbg
2. x64dbg MCP plugin starts HTTP server on 127.0.0.1:8765
3. Malware contains JavaScript that makes XHR requests to localhost
4. Malware reads debugger memory
5. Exfiltrates sensitive data to C2 server

**Impact:** Data exfiltration, debugger manipulation

### Scenario 4: Cache Poisoning Attack

1. Attacker creates malicious binary with known hash
2. Pre-generates fake analysis results
3. Places fake analysis in victim's `~/.ghidra_mcp_cache/`
4. Victim analyzes the binary
5. System loads poisoned cache hiding malicious behavior

**Impact:** Bypassing security analysis

---

## Remediation Roadmap

### Phase 1: Critical Vulnerabilities (Immediate - Week 1)

**Priority P0:**
1. Fix Command Injection in `install.py`
   - Remove `shell=True`
   - Implement secure subprocess handling
   - Add script signature verification

2. Implement Path Sanitization
   - Create `validate_binary_path()` function
   - Apply to all file operations
   - Add path allowlist configuration

3. Add HTTP Server Authentication
   - Implement token-based auth
   - Generate secure random tokens
   - Update Python bridge

### Phase 2: High Vulnerabilities (Week 2-3)

**Priority P1:**
4. Fix Buffer Handling in C++ HTTP Server
5. Add JSON Validation
6. Fix Environment Variable Injection
7. Implement Secure Error Handling

### Phase 3: Medium/Low Vulnerabilities (Week 4-6)

**Priority P2:**
8. Add Input Validation Framework
9. Fix Temporary File Handling
10. Add Concurrency Protection

### Phase 4: Security Hardening (Ongoing)

**Priority P3:**
11. Security Testing (fuzzing, penetration testing)
12. Monitoring and Logging
13. Documentation

### Phase 5: Long-term Improvements

14. Authentication & Authorization
15. Sandboxing
16. Cryptographic Protection

---

## Secure Coding Recommendations

### Input Validation Best Practices

```python
def validate_binary_path(path: str) -> Path:
    """Validate binary file path."""
    p = Path(path).resolve()

    if not p.exists():
        raise ValueError(f"File does not exist: {path}")

    if not p.is_file():
        raise ValueError(f"Path is not a file: {path}")

    max_size = 500 * 1024 * 1024  # 500MB
    if p.stat().st_size > max_size:
        raise ValueError(f"File too large")

    return p
```

### Subprocess Security

```python
# WRONG
subprocess.run("ls -la " + user_input, shell=True)

# CORRECT
subprocess.run(["ls", "-la", user_input], shell=False)
```

### Memory Safety (C++)

```cpp
// Use smart pointers
std::unique_ptr<char[]> buffer(new char[size]);

// Use RAII for socket cleanup
class SocketGuard {
    SOCKET socket_;
public:
    explicit SocketGuard(SOCKET s) : socket_(s) {}
    ~SocketGuard() { if (socket_ != INVALID_SOCKET) closesocket(socket_); }
};
```

---

## Configuration Recommendations

```yaml
# config/security.yaml
security:
  allowed_analysis_directories:
    - ~/malware_samples
    - ~/binary_analysis

  max_binary_size_mb: 500
  max_cache_size_mb: 10000

  analysis_timeout_seconds: 600
  http_request_timeout_seconds: 30

  max_requests_per_minute: 60

  x64dbg_require_auth: true
  x64dbg_bind_localhost_only: true

  log_level: INFO
  audit_log_enabled: true
```

---

## Conclusion

The binary-mcp project has **significant security vulnerabilities** requiring immediate attention:

1. Command injection in installation script (CRITICAL)
2. Path traversal allowing arbitrary file access (HIGH)
3. Unauthenticated HTTP server (HIGH)
4. Insufficient input validation (HIGH)

**Risk Assessment:**
- **Current Risk Level:** HIGH
- **After Phase 1 Fixes:** MEDIUM
- **After Phase 2 Fixes:** LOW
- **After Complete Remediation:** MINIMAL

**Recommendations:**
- Prioritize security fixes before adding new features
- Implement security testing in CI/CD pipeline
- Regular security audits
- Bug bounty program consideration

---

**Assessment Date:** 2025-11-01
**Repository:** binary-mcp v0.2.0
**Assessment Scope:** Full codebase review
**Methodology:** Manual code review, static analysis, threat modeling
