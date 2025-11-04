# devops-policies-opnsense

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Pytest](https://img.shields.io/badge/pytest-7.0%2B-green.svg)](https://docs.pytest.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![TeamCity Build](https://img.shields.io/badge/build-TeamCity-blue.svg)](https://www.jetbrains.com/teamcity/)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![OPNsense](https://img.shields.io/badge/OPNsense-tested-orange.svg)](https://opnsense.org/)

This repository contains pytest-based tests for validating OPNsense firewall configurations, system settings, and operational state.

## Overview

The test suite automatically validates critical OPNsense configurations including:

- **System Settings**: Hostname, domain, DNS servers, NTP configuration, timezone
- **Firewall Rules**: Rule validation, policy compliance, security posture
- **Interface Settings**: Network interface configuration, VLANs, IP assignments
- **Services**: Running services, daemon status, port listeners
- **Security**: Certificate validity, authentication settings, access controls

## Prerequisites

- Python 3.8 or higher
- Access to OPNsense instance (SSH or API)
- Required Python packages (see Installation)

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd opnsense-conftest

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Required Dependencies

```
pytest>=7.0.0
pytest-html>=3.1.0
paramiko>=2.12.0
requests>=2.28.0
pyyaml>=6.0
```

## Configuration

Create a `config.yaml` file with your OPNsense connection details:

```yaml
opnsense:
  host: "192.168.1.1"
  api_key: "your-api-key"
  api_secret: "your-api-secret"
  ssh_user: "root"
  ssh_password: "your-password"  # or use key-based auth
  verify_ssl: false

expected_config:
  hostname: "firewall"
  domain: "example.com"
  dns_servers:
    - "8.8.8.8"
    - "8.8.4.4"
  interfaces:
    - name: "lan"
      ipaddr: "192.168.1.1"
      subnet: 24
    - name: "wan"
      ipaddr: "dhcp"
```

## Usage

### Run All Tests

```bash
pytest
```

### Run Specific Test Categories

```bash
# Test system settings only
pytest tests/test_system.py

# Test firewall rules only
pytest tests/test_firewall.py

# Test interface configuration only
pytest tests/test_interfaces.py
```

### Generate HTML Report

```bash
pytest --html=report.html --self-contained-html
```

### Verbose Output

```bash
pytest -v
```

## Test Structure

```
.
├── conftest.py              # Pytest fixtures and configuration
├── config.yaml              # OPNsense connection and expected config
├── requirements.txt         # Python dependencies
├── tests/
│   ├── test_system.py       # System configuration tests
│   ├── test_firewall.py     # Firewall rule tests
│   ├── test_interfaces.py   # Interface configuration tests
│   ├── test_services.py     # Service status tests
│   └── test_security.py     # Security validation tests
└── README.md
```

## Key Fixtures (conftest.py)

### `opnsense_client`
Provides authenticated connection to OPNsense API or SSH session.

```python
@pytest.fixture
def opnsense_client():
    # Returns configured OPNsense client
    pass
```

### `config`
Loads and provides access to configuration file.

```python
@pytest.fixture
def config():
    # Returns parsed config.yaml
    pass
```

### `system_config`
Fetches current system configuration from OPNsense.

```python
@pytest.fixture
def system_config(opnsense_client):
    # Returns system configuration
    pass
```

## Example Tests

### System Configuration Test

```python
def test_hostname(system_config, config):
    """Verify hostname matches expected configuration"""
    assert system_config['hostname'] == config['expected_config']['hostname']

def test_dns_servers(system_config, config):
    """Verify DNS servers are correctly configured"""
    configured_dns = system_config['dns_servers']
    expected_dns = config['expected_config']['dns_servers']
    assert set(configured_dns) == set(expected_dns)
```

### Firewall Rule Test

```python
def test_default_deny_rule(firewall_rules):
    """Verify default deny rule exists"""
    default_rules = [r for r in firewall_rules if r['action'] == 'block']
    assert len(default_rules) > 0

def test_no_any_any_allow(firewall_rules):
    """Ensure no overly permissive rules exist"""
    dangerous_rules = [
        r for r in firewall_rules 
        if r['action'] == 'pass' and r['source'] == 'any' and r['destination'] == 'any'
    ]
    assert len(dangerous_rules) == 0, "Found overly permissive allow rules"
```

### Interface Test

```python
def test_interface_addresses(interfaces, config):
    """Verify interface IP addresses match configuration"""
    for expected_if in config['expected_config']['interfaces']:
        actual_if = next(i for i in interfaces if i['name'] == expected_if['name'])
        assert actual_if['ipaddr'] == expected_if['ipaddr']
```

## Continuous Integration

### TeamCity Configuration

Create a build configuration in TeamCity with the following setup:

#### Build Steps

**Step 1: Install Dependencies**
```bash
#!/bin/bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

**Step 2: Run Tests**
```bash
#!/bin/bash
source venv/bin/activate
pytest --html=report.html --self-contained-html --junitxml=test-results.xml -v
```

#### Environment Variables

Configure the following parameters in TeamCity (use password type for secrets):

- `OPNSENSE_HOST`: OPNsense firewall hostname/IP
- `OPNSENSE_API_KEY`: API key (password parameter)
- `OPNSENSE_API_SECRET`: API secret (password parameter)
- `OPNSENSE_SSH_USER`: SSH username (if using SSH)
- `OPNSENSE_SSH_PASSWORD`: SSH password (password parameter, if using SSH)

#### Build Features

1. **Python**: Configure Python 3.8+ as build requirement
2. **XML Report Processing**: 
   - Report type: Ant JUnit
   - Monitoring rules: `test-results.xml`
3. **Artifact Paths**: 
   - `report.html => test-reports/`
   - `test-results.xml => test-results/`

#### Build Triggers

- **VCS Trigger**: Run on every commit
- **Schedule Trigger**: Daily at 2:00 AM (for configuration drift detection)
- **Finish Build Trigger**: After related configuration changes

#### Example .teamcity/settings.kts

```kotlin
import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.buildSteps.script
import jetbrains.buildServer.configs.kotlin.triggers.vcs
import jetbrains.buildServer.configs.kotlin.triggers.schedule

object OPNsenseTests : BuildType({
    name = "OPNsense Configuration Tests"
    
    vcs {
        root(DslContext.settingsRoot)
    }
    
    steps {
        script {
            name = "Install Dependencies"
            scriptContent = """
                python3 -m venv venv
                source venv/bin/activate
                pip install --upgrade pip
                pip install -r requirements.txt
            """.trimIndent()
        }
        
        script {
            name = "Run Tests"
            scriptContent = """
                source venv/bin/activate
                pytest --html=report.html --self-contained-html --junitxml=test-results.xml -v
            """.trimIndent()
        }
    }
    
    triggers {
        vcs {
            branchFilter = "+:*"
        }
        schedule {
            schedulingPolicy = daily {
                hour = 2
            }
            branchFilter = "+:main"
            triggerBuild = always()
        }
    }
    
    features {
        feature {
            type = "xml-report-plugin"
            param("xmlReportParsing.reportType", "junit")
            param("xmlReportParsing.reportDirs", "test-results.xml")
        }
    }
    
    artifactRules = """
        report.html => test-reports/
        test-results.xml => test-results/
    """.trimIndent()
    
    params {
        password("env.OPNSENSE_API_KEY", "credentialsJSON:xxx")
        password("env.OPNSENSE_API_SECRET", "credentialsJSON:xxx")
        param("env.OPNSENSE_HOST", "%opnsense.host%")
    }
})
```

## Security Considerations

- **Never commit credentials**: Use environment variables or encrypted secrets
- **API Keys**: Rotate API keys regularly
- **SSH Access**: Prefer key-based authentication over passwords
- **Network Access**: Run tests from secure networks only
- **Least Privilege**: Use read-only API keys when possible

## Troubleshooting

### Connection Timeout

```
Error: Connection to OPNsense timed out
```

**Solution**: Verify network connectivity and firewall rules allow access from test host.

### Authentication Failed

```
Error: Authentication failed
```

**Solution**: Verify API key/secret or SSH credentials are correct.

### SSL Certificate Errors

```
Error: SSL certificate verification failed
```

**Solution**: Set `verify_ssl: false` in config.yaml or add CA certificate to trust store.

## Best Practices

1. **Version Control**: Keep test configuration in version control (except secrets)
2. **Regular Testing**: Schedule automated tests to detect configuration drift
3. **Baseline Testing**: Establish baseline configurations for comparison
4. **Documentation**: Document expected configurations and rationale
5. **Change Management**: Run tests before and after configuration changes

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-test`)
3. Commit your changes (`git commit -am 'Add new test'`)
4. Push to the branch (`git push origin feature/new-test`)
5. Create a Pull Request

## License

[Specify your license here]

## Support

For issues or questions:
- Open an issue in the repository
- Contact: [your-contact-info]

## Changelog

### Version 1.0.0
- Initial release
- System configuration tests
- Firewall rule validation
- Interface configuration tests
- Service status checks
