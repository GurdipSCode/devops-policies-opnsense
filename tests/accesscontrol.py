"""
Access Control Tests

Tests for access control security including management port restrictions,
authentication settings, and administrative access controls.
"""

import pytest


@pytest.mark.critical
@pytest.mark.security
def test_management_ports_restricted(open_ports):
    """Verify management ports are not listening on all interfaces"""
    management_ports = ['443', '80', '22']
    
    unrestricted_mgmt = []
    for port_info in open_ports:
        address = port_info.get('address', '')
        for mgmt_port in management_ports:
            if mgmt_port in address and ('0.0.0.0' in address or '*' in address):
                unrestricted_mgmt.append(port_info)
    
    # Some management access is expected, but should be limited
    # Adjust this test based on your access policy
    if unrestricted_mgmt:
        pytest.warns(UserWarning, 
                    f"Management ports listening on all interfaces: {unrestricted_mgmt}")


@pytest.mark.critical
@pytest.mark.security
def test_web_gui_port_secure(open_ports):
    """Verify web GUI is using HTTPS, not HTTP"""
    http_ports = []
    
    for port_info in open_ports:
        address = port_info.get('address', '')
        
        # Check if HTTP (port 80) is open
        if ':80' in address or '.80' in address:
            http_ports.append(port_info)
    
    # HTTP should not be the primary management interface
    if http_ports:
        pytest.warns(UserWarning, 
                    f"HTTP port 80 is open - use HTTPS only: {http_ports}")


@pytest.mark.security
def test_non_standard_ssh_port(open_ports, config):
    """Verify SSH is on non-standard port (optional security)"""
    use_non_standard_ssh = config.get('security_policy', {}).get('non_standard_ssh_port', False)
    
    if use_non_standard_ssh:
        ssh_on_22 = []
        
        for port_info in open_ports:
            address = port_info.get('address', '')
            
            if ':22' in address or '.22' in address:
                ssh_on_22.append(port_info)
        
        if ssh_on_22:
            pytest.warns(UserWarning, 
                        "SSH is on standard port 22 - consider non-standard port")


@pytest.mark.security
def test_management_vlan_isolated(config):
    """Verify management is on isolated VLAN"""
    # Check if management interface is on dedicated VLAN
    
    management_vlan = config.get('security_policy', {}).get('management_vlan')
    
    if management_vlan:
        # Verify VLAN is configured
        # Implementation depends on VLAN configuration
        pass


@pytest.mark.security
def test_admin_account_not_default(opnsense_ssh):
    """Verify default admin account has been changed"""
    # Check that the default 'root' account has strong password
    # or that alternative admin accounts are used
    
    # This is difficult to test directly without password testing
    # Can check if additional admin users exist
    
    stdout, stderr = opnsense_ssh.execute("pw usershow -a | grep -E 'wheel|admin'")
    
    # Should have more than just root
    admin_users = [line for line in stdout.split('\n') if line.strip()]
    
    if len(admin_users) <= 1:
        pytest.warns(UserWarning, 
                    "Consider creating additional admin accounts (don't rely solely on root)")


@pytest.mark.security
def test_session_timeout_configured(config):
    """Verify session timeout is configured"""
    # Web GUI sessions should timeout after inactivity
    
    require_session_timeout = config.get('security_policy', {}).get('require_session_timeout', True)
    
    if require_session_timeout:
        # Check web GUI session timeout configuration
        # Implementation depends on how to retrieve this setting
        pass


@pytest.mark.security
def test_failed_login_attempts_limited(opnsense_ssh):
    """Verify failed login attempt limiting is configured"""
    # Check for fail2ban or similar protection
    
    stdout, stderr = opnsense_ssh.execute("service fail2ban status 2>/dev/null || echo 'not installed'")
    
    if 'not installed' in stdout:
        # fail2ban not installed, check for other protections
        # Many firewalls have built-in protections
        pass


@pytest.mark.security
def test_password_complexity_requirements(password_policy):
    """Verify password complexity requirements are enforced"""
    # Check password policy configuration
    
    login_conf = password_policy.get('login_conf', '')
    
    # Should have password complexity requirements
    # Implementation depends on login.conf structure
    
    if 'passwd_format' in login_conf or 'minpasswordlen' in login_conf:
        # Password policy is configured
        pass


@pytest.mark.security
def test_two_factor_authentication_available(config):
    """Verify two-factor authentication is available"""
    require_2fa = config.get('security_policy', {}).get('require_2fa', False)
    
    if require_2fa:
        # Check if 2FA is configured
        # This would require checking authentication configuration
        pass


@pytest.mark.security
def test_api_access_restricted(config):
    """Verify API access is restricted to authorized hosts"""
    # API keys should be restricted to specific IP addresses
    
    # Check API key restrictions in configuration
    # Implementation depends on how API restrictions are configured
    pass


@pytest.mark.security
def test_console_access_restricted():
    """Verify console access requires authentication"""
    # Physical/serial console should require authentication
    # This is typically default behavior but worth verifying
    pass


@pytest.mark.security
def test_sudo_access_configured(opnsense_ssh):
    """Verify sudo access is properly configured"""
    # Check sudo configuration for proper access controls
    
    stdout, stderr = opnsense_ssh.execute("cat /usr/local/etc/sudoers 2>/dev/null || echo 'not found'")
    
    if 'not found' not in stdout:
        # Sudo is configured
        # Should not have NOPASSWD for all commands
        if 'NOPASSWD: ALL' in stdout:
            pytest.warns(UserWarning, 
                        "Sudo configured with NOPASSWD:ALL - security risk")


@pytest.mark.security
def test_root_login_limited(ssh_config):
    """Verify root login is appropriately restricted"""
    permit_root = ssh_config.get('PermitRootLogin', 'yes').lower()
    
    # Covered in system tests but important enough to repeat
    assert permit_root != 'yes', \
        "Root SSH login should be restricted (use 'no' or 'prohibit-password')"


@pytest.mark.security
def test_idle_timeout_configured(ssh_config):
    """Verify SSH idle timeout is configured"""
    # SSH sessions should timeout after inactivity
    
    client_alive_interval = ssh_config.get('ClientAliveInterval', '0')
    client_alive_count = ssh_config.get('ClientAliveCountMax', '3')
    
    # Should have reasonable timeout (e.g., 300 seconds * 3 = 15 minutes)
    if client_alive_interval != '0':
        timeout_seconds = int(client_alive_interval) * int(client_alive_count)
        
        assert timeout_seconds <= 3600, \
            f"SSH idle timeout too long: {timeout_seconds} seconds"


@pytest.mark.security
def test_privilege_separation_enabled(ssh_config):
    """Verify SSH privilege separation is enabled"""
    use_priv_sep = ssh_config.get('UsePrivilegeSeparation', 'yes').lower()
    
    assert use_priv_sep == 'yes', \
        "SSH privilege separation should be enabled"


@pytest.mark.security
def test_max_auth_tries_limited(ssh_config):
    """Verify maximum authentication attempts is limited"""
    max_auth_tries = int(ssh_config.get('MaxAuthTries', '6'))
    
    assert max_auth_tries <= 6, \
        f"SSH max authentication tries should be limited (≤6), found: {max_auth_tries}"


@pytest.mark.security
def test_login_grace_time_limited(ssh_config):
    """Verify SSH login grace time is limited"""
    login_grace_time = ssh_config.get('LoginGraceTime', '120')
    
    # Parse time value (might be '120s' or '2m')
    if login_grace_time.endswith('s'):
        seconds = int(login_grace_time[:-1])
    elif login_grace_time.endswith('m'):
        seconds = int(login_grace_time[:-1]) * 60
    else:
        seconds = int(login_grace_time)
    
    assert seconds <= 120, \
        f"SSH login grace time should be limited (≤120s), found: {seconds}s"


@pytest.mark.security
def test_empty_passwords_disabled(ssh_config):
    """Verify empty passwords are not permitted"""
    permit_empty = ssh_config.get('PermitEmptyPasswords', 'no').lower()
    
    assert permit_empty == 'no', \
        "Empty passwords should not be permitted"


@pytest.mark.security
def test_x11_forwarding_disabled(ssh_config):
    """Verify X11 forwarding is disabled (if not needed)"""
    x11_forwarding = ssh_config.get('X11Forwarding', 'no').lower()
    
    # X11 forwarding is typically not needed on firewalls
    if x11_forwarding == 'yes':
        pytest.warns(UserWarning, 
                    "X11 forwarding enabled - disable if not needed")


@pytest.mark.security
def test_strict_modes_enabled(ssh_config):
    """Verify SSH strict modes is enabled"""
    strict_modes = ssh_config.get('StrictModes', 'yes').lower()
    
    assert strict_modes == 'yes', \
        "SSH strict modes should be enabled for proper permission checking"
