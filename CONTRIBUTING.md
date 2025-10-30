# Contributing to Ghidra MCP Server

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- This is a security research tool - use responsibly
- Follow ethical hacking principles

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in Issues
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - System info (OS, Python version, Ghidra version)
   - Relevant logs or error messages

### Suggesting Features

1. Check if the feature has been suggested
2. Create an issue describing:
   - Use case and motivation
   - Proposed implementation (if applicable)
   - Examples of how it would be used
   - Any potential challenges

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow code style guidelines (see below)
   - Add tests for new functionality
   - Update documentation

4. **Run tests**
   ```bash
   make test
   ```

5. **Commit your changes**
   - Use conventional commits format:
     - `feat: Add new tool for X`
     - `fix: Resolve issue with Y`
     - `docs: Update README for Z`
     - `test: Add tests for W`
     - `refactor: Improve V`

6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**
   - Describe what you changed and why
   - Reference any related issues
   - Ensure CI passes

## Development Setup

### Prerequisites

- Python 3.12+
- Ghidra installation
- Java 21+
- uv package manager

### Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/ghidra-mcp-headless.git
cd ghidra-mcp-headless

# Install dependencies
make install-dev

# Run tests
make test

# Run with coverage
make test-cov
```

## Code Style

### Python Style

- **PEP 8** compliant
- **Type hints** for all function signatures
- **Docstrings** for all public functions (Google style)
- **Max line length**: 100 characters

### Example:

```python
def analyze_function(
    binary_path: str,
    function_name: str,
    depth: int = 2
) -> dict:
    """
    Analyze a specific function in the binary.

    Args:
        binary_path: Path to the binary file
        function_name: Name of function to analyze
        depth: Analysis depth level

    Returns:
        Dictionary containing analysis results

    Raises:
        FileNotFoundError: If binary doesn't exist
        ValueError: If function not found
    """
    # Implementation
    pass
```

### Code Quality Tools

```bash
# Lint code
make lint

# Format code
make format
```

## Testing

### Writing Tests

- Add tests for all new features
- Aim for >80% code coverage
- Use pytest fixtures for common setup
- Mock external dependencies (Ghidra, filesystem)

### Test Structure

```python
def test_feature_name():
    """Test description."""
    # Arrange
    setup_test_data()

    # Act
    result = function_under_test()

    # Assert
    assert result == expected_value
```

### Running Tests

```bash
# All tests
make test

# Specific test file
uv run pytest tests/test_server.py

# Specific test function
uv run pytest tests/test_server.py::test_function_name

# With coverage
make test-cov
```

## Adding New MCP Tools

1. **Add tool function** in `src/server.py`:

```python
@app.tool()
def your_new_tool(
    binary_path: str,
    param: str = "default"
) -> str:
    """
    Brief description of what this tool does.

    Args:
        binary_path: Path to analyzed binary
        param: Description of parameter

    Returns:
        Formatted output string
    """
    try:
        context = get_analysis_context(binary_path)

        # Your implementation
        result = process_data(context, param)

        return format_output(result)

    except Exception as e:
        logger.error(f"your_new_tool failed: {e}")
        return f"Error: {e}"
```

2. **Add tests** in `tests/test_server.py`

3. **Update README.md** with tool documentation

4. **Update CLAUDE.md** if it affects architecture

## Extending Pattern Databases

### Adding API Patterns

Edit `src/utils/patterns.py`:

```python
"NewAPIFunction": {
    "category": "network",  # process, memory, file, etc.
    "severity": "high",     # critical, high, medium, low
    "description": "Brief description of what this API does"
}
```

### Adding Crypto Patterns

```python
"new_algorithm": {
    "algorithm": "AES",
    "pattern": "hexpattern",
    "description": "What this pattern indicates"
}
```

## Documentation

### README Updates

- Keep usage examples up-to-date
- Add new tools to the tool reference
- Update configuration examples if needed

### Code Documentation

- Document all public functions with docstrings
- Add inline comments for complex logic
- Update CLAUDE.md for architectural changes

## Git Workflow

### Branch Naming

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation only
- `refactor/` - Code refactoring
- `test/` - Test additions/fixes

### Commit Messages

Follow conventional commits:

```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting, missing semicolons, etc.
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

**Example:**

```
feat: Add YARA rule scanning tool

Implements a new MCP tool that scans binaries with YARA rules.
Supports custom rule files and outputs matches with metadata.

Closes #42
```

## Review Process

### What We Look For

1. **Functionality**: Does it work as intended?
2. **Tests**: Are there adequate tests?
3. **Documentation**: Is it well documented?
4. **Code Quality**: Follows style guidelines?
5. **Security**: No security issues introduced?
6. **Performance**: Reasonable performance?

### Review Timeline

- We aim to review PRs within 1 week
- Complex changes may take longer
- Feel free to ping if no response after 2 weeks

## Security

### Reporting Security Issues

**Do not** create public issues for security vulnerabilities.

Instead, email: security@[project-domain].com

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Considerations

- This tool performs static analysis only
- Never execute malware samples
- Always analyze in isolated environments
- Validate all user inputs
- Be cautious with file operations

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

- Open an issue for general questions
- Check CLAUDE.md for technical details
- See README.md for usage information

## Thank You!

Your contributions make this project better for everyone in the security research community!
