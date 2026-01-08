# Development Guide

Complete guide for developing and contributing to Linux Health Security Scanner.

## Setup Development Environment

### Prerequisites
- Python 3.11+
- Git
- SSH client
- Docker (optional, for container testing)

### Initial Setup

```bash
# Clone repository
git clone <repo-url>
cd linux_health

# Create virtual environment
python3.11 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Project Architecture

### Module Responsibilities

#### `__main__.py`
Entry point for the CLI application.

#### `cli.py`
Command-line interface and orchestration:
- Argument parsing (argparse)
- SSH connection management
- Report generation and output
- Password handling
- Optional scans coordination

#### `ssh_client.py`
SSH session wrapper around Paramiko:
- Connection establishment
- Command execution with timeout
- Error handling
- Session cleanup

#### `checks.py`
Core security check functions (36+):
- Modular check design
- Each check returns `CheckResult`
- Helper functions: `_run()`, `_pass()`, `_warn()`, `_fail()`
- Optional scans: rkhunter, package hygiene

#### `report.py`
Report generation:
- Text format rendering
- Markdown format rendering
- System information collection
- Port scan result formatting
- Status summary calculation

#### `scanner.py`
TCP port scanning:
- Connect-based port detection
- Timeout handling
- Results formatting

## Coding Standards

### Style Guide
- Follow PEP 8 (enforced by Black)
- Use type hints for new code
- Google-style docstrings
- Max line length: 88 characters

### Code Quality Checks

```bash
# Format code with Black
black linux_health/ tests/

# Check with Ruff (linter)
ruff check linux_health/ tests/

# Auto-fix issues
ruff check --fix linux_health/ tests/

# Combined check
black --check linux_health/ tests/ && ruff check linux_health/ tests/
```

## Adding New Security Checks

### Step 1: Implement Check Function

Add to `linux_health/checks.py`:

```python
def check_new_vulnerability(ssh: SSHSession, password: str = "") -> CheckResult:
    """
    Check for new vulnerability or security issue.
    
    Args:
        ssh: SSH session
        password: User password for sudo commands (if needed)
    
    Returns:
        CheckResult with status, details, and recommendations
    """
    category = "Security Category"
    
    try:
        # Run detection command
        code, out, err = _run(ssh, "detection_command")
        
        # Check for issues
        if code != 0:
            return _fail(
                "Issue Name",
                "What was found",
                "How to fix it",
                category
            )
        
        if "warning_indicator" in out:
            return _warn(
                "Issue Name",
                "What might be wrong",
                "Recommended action",
                category
            )
        
        return _pass(
            "Issue Name",
            "Everything looks good",
            "No action needed",
            category
        )
    
    except Exception as e:
        return _fail(
            "Issue Name",
            f"Could not check: {e}",
            "Check error logs",
            category
        )
```

### Step 2: Add to Check Runner

In `run_all_checks()` function:

```python
results.append(check_new_vulnerability(ssh, password))
```

### Step 3: Write Unit Tests

Add to `tests/test_linux_health.py`:

```python
class TestNewVulnerability:
    """Test suite for new vulnerability check."""
    
    def test_pass_when_no_issues(self):
        """Test that check passes when no vulnerability found."""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "safe_output", ""))
        
        result = check_new_vulnerability(mock_ssh)
        
        assert result.status == "pass"
        assert "Issue Name" in result.title
    
    def test_warn_on_warning_condition(self):
        """Test that check warns on potential issue."""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "warning_indicator found", ""))
        
        result = check_new_vulnerability(mock_ssh)
        
        assert result.status == "warn"
        assert result.recommendation != ""
    
    def test_fail_on_critical_issue(self):
        """Test that check fails on critical issue."""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(1, "", "error"))
        
        result = check_new_vulnerability(mock_ssh)
        
        assert result.status == "fail"
        assert result.recommendation != ""
    
    def test_handles_ssh_error(self):
        """Test graceful error handling."""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(side_effect=Exception("SSH error"))
        
        result = check_new_vulnerability(mock_ssh)
        
        assert result.status == "fail"
```

### Step 4: Test Locally

```bash
# Run specific test
pytest tests/test_linux_health.py::TestNewVulnerability -v

# Run all tests
pytest tests/ -v

# Check coverage for new code
pytest tests/ --cov=linux_health --cov-report=html
```

### Step 5: Update Documentation

- Add check to [Security Checks](#security-checks) table in README.md
- Document detection method and thresholds
- Add to CHANGELOG.md if significant

## Testing Best Practices

### Unit Test Template

```python
from unittest.mock import Mock, MagicMock
from linux_health.checks import check_something

class TestSomething:
    """Tests for check_something function."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.mock_ssh = Mock()
    
    def test_success_case(self):
        """Happy path test."""
        self.mock_ssh.run = MagicMock(return_value=(0, "output", ""))
        result = check_something(self.mock_ssh)
        assert result.status == "pass"
    
    def test_failure_case(self):
        """Failure case test."""
        self.mock_ssh.run = MagicMock(return_value=(1, "", "error"))
        result = check_something(self.mock_ssh)
        assert result.status == "fail"
    
    def test_warning_case(self):
        """Warning case test."""
        self.mock_ssh.run = MagicMock(return_value=(0, "warning", ""))
        result = check_something(self.mock_ssh)
        assert result.status == "warn"
```

### Running Tests

```bash
# All tests
pytest tests/

# Specific test class
pytest tests/test_linux_health.py::TestCheckDiskUsage

# Specific test method
pytest tests/test_linux_health.py::TestCheckDiskUsage::test_high_disk_usage

# Verbose output
pytest tests/ -v

# Show print statements
pytest tests/ -s

# Stop on first failure
pytest tests/ -x

# Coverage report
pytest tests/ --cov=linux_health --cov-report=term-missing
```

## Building Docker Image

### Local Build

```bash
# Build image
docker build -t linux-health:latest .

# Build with specific Python version
docker build --build-arg PYTHON_VERSION=3.11 -t linux-health:3.11 .

# Build without cache
docker build --no-cache -t linux-health:latest .
```

### Testing Docker Build

```bash
# Run a scan with Docker
docker run --rm linux-health 192.168.1.100 user password

# Run with volume mount
docker run --rm -v "$(pwd):/reports" linux-health \
  192.168.1.100 user password --format md --output /reports/report.md

# Interactive with debugging
docker run -it --rm linux-health bash
```

### Docker Troubleshooting

```bash
# Check image layers
docker history linux-health:latest

# Inspect image
docker inspect linux-health:latest

# Run with verbose output
docker run --rm -e PYTHONUNBUFFERED=1 linux-health host user pass

# View image size
docker images linux-health
```

## Git Workflow

### Branch Naming

- `feature/description` - New features
- `bugfix/description` - Bug fixes
- `docs/description` - Documentation only
- `test/description` - Test improvements

### Commit Messages

```
<type>(<scope>): <subject>

<body>

<footer>
```

Example:
```
feat(checks): add new privilege escalation check

Added check_capabilities function to detect dangerous capabilities.
Implements SUID capability detection for privilege escalation risks.

Closes #42
```

### Pull Request Process

1. Create feature branch
2. Make changes with tests
3. Run full test suite
4. Ensure 100% linting pass
5. Update documentation
6. Create PR with detailed description
7. Address review feedback

## Performance Optimization

### Current Performance

- Per-host scan: 30-60 seconds
- SSH overhead: 2-5 seconds
- Check execution: 25-55 seconds
- Port scan: 5-10 seconds

### Optimization Opportunities

1. **Parallel Check Execution**
   - Use asyncio or threading for I/O-bound checks
   - SSH session pooling for multiple commands

2. **Result Caching**
   - Cache similar check results
   - Skip redundant system queries

3. **Batch Command Execution**
   - Group related checks into single SSH command
   - Parse results for multiple checks

4. **Port Scanner Optimization**
   - Implement faster async scanning
   - Use threading for parallel port checks

## Debugging

### Enable Debug Logging

```python
# In cli.py
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Then in checks:
logger.debug(f"Check output: {out}")
```

### SSH Debugging

```bash
# Enable SSH verbose logging
ssh -vvv user@host

# Test SSH connectivity before running scanner
ssh -n user@host "hostname"
```

### Mock Testing

```python
# Mock SSH responses
mock_ssh = Mock()
mock_ssh.run = MagicMock(
    side_effect=[
        (0, "first_command_output", ""),
        (0, "second_command_output", "")
    ]
)
```

## Release Process

### Version Numbering

Follow semantic versioning: MAJOR.MINOR.PATCH

- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests passing
- [ ] All linting checks passing
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version number updated (setup.py, __init__.py)
- [ ] Git tag created: `git tag v1.0.0`
- [ ] Release notes written
- [ ] Docker image tagged and pushed

## Continuous Integration Ideas

### GitHub Actions Workflow

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.11, 3.12]
    
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: pip install -r requirements-dev.txt
      - name: Lint with Ruff
        run: ruff check .
      - name: Format check with Black
        run: black --check .
      - name: Run tests
        run: pytest tests/ --cov=linux_health
```

## Troubleshooting Development Issues

### Import Errors

```bash
# Reinstall package in development mode
pip install -e .

# Verify module structure
python -c "import linux_health; print(linux_health.__file__)"
```

### Test Failures

```bash
# Run test with full traceback
pytest tests/ -vv --tb=long

# Run test with print output
pytest tests/ -s

# Drop into debugger on failure
pytest tests/ --pdb
```

### Linting Failures

```bash
# Auto-fix all issues
ruff check --fix .
black .

# Check specific file
ruff check linux_health/checks.py
```

---

For questions or issues, open a GitHub issue or contact the maintainers.
