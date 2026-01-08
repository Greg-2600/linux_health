# Testing Documentation

## Test Coverage Report

**Overall Coverage: 61%** (87/87 tests passing)

### Module Coverage Breakdown

| Module | Lines | Covered | Coverage | Key Coverage |
|--------|-------|---------|----------|--------------|
| `checks.py` | 941 | 645 | 69% | Most security check functions |
| `cli.py` | 66 | 38 | 58% | Argument parsing, main flow |
| `report.py` | 270 | 109 | 40% | Report generation paths |
| `scanner.py` | 29 | 13 | 45% | Port scanning |
| `ssh_client.py` | 33 | 10 | 30% | SSH connection wrapper |

### Test Summary

- **Total Tests**: 87
- **Pass Rate**: 100%
- **Execution Time**: ~1 second
- **Framework**: pytest

## Test Categories

### 1. Check Logic Tests (70+ tests)
Tests for each of the 36+ security checks:
- Pass scenarios
- Warn scenarios
- Fail scenarios
- Error handling

**Examples:**
- `TestCheckDiskUsage` - Disk usage detection
- `TestCheckMemory` - Memory availability
- `TestCheckSSHConfig` - SSH security
- `TestCryptoMiners` - Malware detection
- `TestPrivilegeEscalationVectors` - Privilege escalation detection

### 2. CLI Tests (9 tests)
Command-line argument and orchestration:
- Port parsing
- Argument validation
- Report output formats
- Password handling

**Examples:**
- `TestParsePortsUtil` - Port specification parsing
- `TestBuildParser` - Argument parser validation
- `TestRenderReportPorts` - Port report formatting

### 3. Data Structure Tests (8 tests)
Core data types and results:
- CheckResult creation
- SystemInfo creation
- DetailedSecurityInfo creation
- Report rendering

**Examples:**
- `TestCheckResult` - Result status/details
- `TestSystemInfo` - System information
- `TestDetailedSecurityInfo` - Full security report

## Running Tests

### Quick Test Run
```bash
# Run all tests
pytest tests/

# Quick output (summary only)
pytest tests/ -q

# Verbose with test names
pytest tests/ -v
```

### With Coverage
```bash
# Generate coverage report (terminal)
pytest tests/ --cov=linux_health --cov-report=term-missing

# Generate HTML coverage report
pytest tests/ --cov=linux_health --cov-report=html
# Open htmlcov/index.html in browser

# Coverage with branch analysis
pytest tests/ --cov=linux_health --cov-report=term:skip-covered --cov-branch
```

### Specific Tests
```bash
# Run single test class
pytest tests/test_linux_health.py::TestCheckDiskUsage -v

# Run single test method
pytest tests/test_linux_health.py::TestCheckDiskUsage::test_high_disk_usage -v

# Run tests matching pattern
pytest tests/ -k "crypto" -v
pytest tests/ -k "privilege" -v
pytest tests/ -k "pass" -v  # Tests with "pass" in name
```

### Advanced Testing
```bash
# Stop on first failure
pytest tests/ -x

# Show local variables on failure
pytest tests/ -l

# Full traceback
pytest tests/ -vv --tb=long

# Show print output
pytest tests/ -s

# Run in random order
pip install pytest-random-order
pytest tests/ -p no:randomly  # Disable random order

# Run in parallel (faster)
pip install pytest-xdist
pytest tests/ -n auto

# Generate JUnit XML report
pytest tests/ --junit-xml=report.xml
```

## Test Structure Example

```python
from unittest.mock import Mock, MagicMock, patch
from linux_health.checks import check_disk_usage
from linux_health import CheckResult

class TestCheckDiskUsage:
    """Test suite for disk usage check."""
    
    def setup_method(self):
        """Setup before each test."""
        self.mock_ssh = Mock()
    
    def teardown_method(self):
        """Cleanup after each test."""
        self.mock_ssh = None
    
    def test_low_disk_usage_passes(self):
        """Test that low disk usage passes."""
        # Setup
        self.mock_ssh.run = MagicMock(return_value=(0, "50%", ""))
        
        # Execute
        result = check_disk_usage(self.mock_ssh)
        
        # Assert
        assert result.status == "pass"
        assert result.title == "Disk usage"
        assert "50%" in result.details
    
    def test_high_disk_usage_warns(self):
        """Test that 80% usage triggers warning."""
        self.mock_ssh.run = MagicMock(return_value=(0, "80%", ""))
        result = check_disk_usage(self.mock_ssh)
        assert result.status == "warn"
    
    def test_critical_disk_usage_fails(self):
        """Test that 90%+ usage fails."""
        self.mock_ssh.run = MagicMock(return_value=(0, "95%", ""))
        result = check_disk_usage(self.mock_ssh)
        assert result.status == "fail"
    
    def test_command_failure_handling(self):
        """Test error handling."""
        self.mock_ssh.run = MagicMock(side_effect=Exception("SSH error"))
        result = check_disk_usage(self.mock_ssh)
        assert result.status == "fail"
```

## Improving Coverage

### Areas Needing More Tests

1. **ssh_client.py (30% coverage)**
   - SSH connection establishment
   - Command timeout handling
   - Connection error scenarios
   - Add tests with timeout mocking

2. **report.py (40% coverage)**
   - Markdown formatting edge cases
   - Report with no findings
   - Report with all failures
   - Large result sets
   - Special characters in output

3. **scanner.py (45% coverage)**
   - Timeout scenarios
   - Unreachable hosts
   - Filtered ports
   - Large port lists

### Adding Integration Tests

For real test environment:

```python
# tests/integration_test.py (future)
import pytest
from linux_health.cli import main

@pytest.mark.integration
def test_full_scan_against_local_host():
    """Test full scan against local SSH server."""
    # This would require a running SSH server
    # Useful for CI/CD pipelines
    pass

@pytest.mark.integration
def test_docker_scan():
    """Test scanning Docker container."""
    # Start test container
    # Run scan
    # Verify results
    pass
```

## Continuous Integration Recommendations

### GitHub Actions Workflow

```yaml
name: Tests & Quality

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.11', '3.12']
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      
      - name: Lint with Ruff
        run: ruff check linux_health/ tests/
      
      - name: Format check with Black
        run: black --check linux_health/ tests/
      
      - name: Run tests
        run: pytest tests/ --cov=linux_health --cov-report=xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml
```

## Test Maintenance

### Adding New Tests

1. Create test class following naming convention: `Test<FunctionName>`
2. Use descriptive test method names: `test_<scenario>_<expected_result>`
3. Follow AAA pattern: Arrange, Act, Assert
4. Mock all external dependencies
5. Test both success and failure paths

### Updating Existing Tests

When modifying check functions:
1. Update related tests
2. Ensure all tests pass
3. Update test docstrings if behavior changes
4. Verify coverage didn't decrease

### Test Naming Convention

```python
# Bad
def test_disk():
    pass

# Good
def test_high_disk_usage_fails_with_appropriate_recommendation():
    pass

# Acceptable
def test_disk_high_usage_fails():
    pass
```

## Performance Testing

### Benchmark Individual Checks

```bash
# Run with timing
pytest tests/ -v --durations=10

# Profile test execution
pip install pytest-profiling
pytest tests/ --profile
```

### Load Testing

For testing against real systems:

```python
# tests/performance_test.py (future)
import time
from linux_health.cli import scan_host

def test_scan_performance():
    """Ensure scan completes in reasonable time."""
    start = time.time()
    results = scan_host("192.168.1.100", "user", "pass")
    duration = time.time() - start
    
    assert duration < 60, "Scan took longer than 60 seconds"
    assert len(results) == 36, "All checks should complete"
```

## Debugging Failed Tests

### Pytest Debug Mode

```bash
# Drop into debugger on failure
pytest tests/ --pdb

# Drop into debugger on error (not just failure)
pytest tests/ --pdbcls=IPython.terminal.debugger:TerminalPdb

# Post-mortem debugging
pytest tests/ --pdb --pdbcls=IPython.terminal.debugger:TerminalPdb
```

### Print Debugging

```bash
# Show print statements (normally hidden)
pytest tests/ -s

# Show even in passing tests
pytest tests/ -s -v

# Capture log output
pytest tests/ --log-cli-level=DEBUG
```

## Test Isolation

Ensure tests don't interfere:

```python
# Good: Each test is independent
class TestChecks:
    def setup_method(self):
        """Run before each test."""
        self.mock_ssh = Mock()
    
    def teardown_method(self):
        """Clean up after each test."""
        del self.mock_ssh
    
    def test_one(self):
        pass
    
    def test_two(self):
        # test_two won't be affected by test_one
        pass
```

## Documentation Standards

### Test Docstrings

```python
def test_disk_usage_high_fails(self):
    """
    Test that disk usage above 90% fails the check.
    
    Given: Disk usage reported as 94%
    When: check_disk_usage is called
    Then: Result status should be 'fail' with remediation steps
    """
```

---

For more information, see DEVELOPMENT.md for contributing guidelines.
