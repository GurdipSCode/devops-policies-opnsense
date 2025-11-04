"""
System Configuration Tests

Tests for system-level security settings including SSH, logging,
NTP synchronization, and update status.
"""

import pytest
from datetime import datetime


@pytest.mark.critical
@pytest.mark.security
@pytest.mark.system
def test_ssh_root_login_disabled(ssh_config):
    """Verify root login via SSH is disabled"""
    permit_root = ssh_config.get('PermitRootLogin', 'yes').lower()
    assert permit_root in ['no', 'prohibit-password', 'forced-commands-only'], \
        "Root login should be disabled or restricted"


@pytest.mark.critical
@pytest.mark.security
@pytest.mark.system
def test_ssh_password_authentication(ssh_config):
    """Verify password authentication is appropriately configured"""
    password_auth = ssh_config.get('PasswordAuthentication', 'yes').lower()
    # This test can be adjusted based on your security policy
    assert password_auth in ['yes', 'no'], \
        f"PasswordAuthentication has unexpected value: {password_auth}"


@pytest.mark.critical
@pytest.mark.security
@pytest.mark.system
def test_ssh_protocol_version(ssh_config):
    """Verify SSH protocol version 2 is enforced"""
    protocol = ssh_config.get('Protocol', '2')
    assert '2' in protocol and '1' not in protocol, \
        "Only SSH protocol version 2 should be enabled"


@pytest.mark.security
@pytest.mark.system
def test_syslog_enabled(syslog_config):
    """Verify syslog is properly configured"""
    assert syslog_config['syslog_conf'], "Syslog configuration should not be empty"


@pytest.mark.security
@pytest.mark.system
def test_remote_syslog_configured(syslog_config, config):
    """Verify remote syslog is configured (if required by policy)"""
    # Adjust this test based on your logging requirements
    if config.get('security_policy', {}).get('require_remote_logging', False):
        assert syslog_config['remote_logging_enabled'], \
            "Remote syslog should be configured per security policy"


@pytest.mark.security
def test_ntp_synchronized(ntp_config):
    """Verify NTP is synchronized"""
    ntp_output = ntp_config['ntp_output']
    
    # Check for synchronized peers (marked with *)
    synchronized = any('*' in line for line in ntp_output.split('\n'))
    
    assert synchronized, "NTP should be synchronized with at least one peer"


@pytest.mark.security
@pytest.mark.system
def test_system_version_current(update_status, config):
    """Verify OPNsense is running a current version"""
    current_version = update_status['current_version']
    
    # You would need to implement logic to check against latest version
    # This is a placeholder test
    assert current_version, "System version should be detectable"
    
    # Add version comparison logic based on your update policy
    min_version = config.get('security_policy', {}).get('min_opnsense_version')
    if min_version:
        # Implement version comparison
        pass


@pytest.mark.security
@pytest.mark.system
def test_hostname_configured(system_info, config):
    """Verify hostname is properly configured"""
    expected_hostname = config.get('expected_config', {}).get('hostname')
    if expected_hostname:
        actual_hostname = system_info.get('hostname', '')
        assert actual_hostname == expected_hostname, \
            f"Hostname mismatch. Expected: {expected_hostname}, Found: {actual_hostname}"


@pytest.mark.security
@pytest.mark.system
def test_timezone_configured(config):
    """Verify timezone is properly configured"""
    expected_timezone = config.get('expected_config', {}).get('timezone')
    if expected_timezone:
        # This would need to be implemented based on how you retrieve timezone
        # from OPNsense
        pass
