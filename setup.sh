#!/bin/bash
# OPNsense Test Suite Setup Script
# 
# This script sets up the complete test suite structure and initializes
# the testing environment.

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python 3 installed: $PYTHON_VERSION"
    else
        print_error "Python 3 not found. Please install Python 3.8 or higher."
        exit 1
    fi
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        print_success "pip3 installed"
    else
        print_error "pip3 not found. Please install pip."
        exit 1
    fi
    
    # Check git (optional)
    if command -v git &> /dev/null; then
        print_success "Git installed"
    else
        print_warning "Git not found (optional)"
    fi
    
    echo ""
}

# Create directory structure
create_directories() {
    print_header "Creating Directory Structure"
    
    mkdir -p tests
    mkdir -p test-reports
    mkdir -p .github/workflows
    
    print_success "Created tests/ directory"
    print_success "Created test-reports/ directory"
    print_success "Created .github/workflows/ directory"
    
    echo ""
}

# Setup Python virtual environment
setup_venv() {
    print_header "Setting Up Virtual Environment"
    
    if [ -d "venv" ]; then
        print_warning "Virtual environment already exists"
        read -p "Remove and recreate? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf venv
            print_info "Removed existing virtual environment"
        else
            print_info "Keeping existing virtual environment"
            return
        fi
    fi
    
    python3 -m venv venv
    print_success "Created virtual environment"
    
    # Activate virtual environment
    source venv/bin/activate 2>/dev/null || . venv/bin/activate
    print_success "Activated virtual environment"
    
    # Upgrade pip
    pip install --upgrade pip -q
    print_success "Upgraded pip"
    
    echo ""
}

# Install dependencies
install_dependencies() {
    print_header "Installing Dependencies"
    
    if [ ! -f "requirements.txt" ]; then
        print_error "requirements.txt not found"
        exit 1
    fi
    
    # Activate venv if not already active
    if [ -z "$VIRTUAL_ENV" ]; then
        source venv/bin/activate 2>/dev/null || . venv/bin/activate
    fi
    
    pip install -r requirements.txt
    print_success "Installed all dependencies"
    
    echo ""
}

# Setup configuration
setup_config() {
    print_header "Setting Up Configuration"
    
    if [ -f "config.yaml" ]; then
        print_warning "config.yaml already exists"
        read -p "Overwrite with template? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Keeping existing config.yaml"
            return
        fi
    fi
    
    # Create config from template (config.yaml already exists as the template)
    if [ -f "config.yaml" ]; then
        print_success "config.yaml ready for customization"
        print_warning "⚠ IMPORTANT: Edit config.yaml with your OPNsense credentials"
        print_info "  1. Set host (OPNsense IP address)"
        print_info "  2. Set api_key and api_secret"
        print_info "  3. Configure expected settings"
    else
        print_error "config.yaml template not found"
        exit 1
    fi
    
    # Set secure permissions on config.yaml
    chmod 600 config.yaml
    print_success "Set secure permissions (600) on config.yaml"
    
    echo ""
}

# Initialize git repository
init_git() {
    print_header "Git Repository Setup"
    
    if [ -d ".git" ]; then
        print_warning "Git repository already initialized"
        return
    fi
    
    read -p "Initialize git repository? (y/n): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git init
        print_success "Initialized git repository"
        
        # Add .gitignore if it doesn't exist
        if [ ! -f ".gitignore" ]; then
            print_error ".gitignore not found"
        else
            git add .gitignore
            print_success "Added .gitignore"
        fi
        
        print_warning "⚠ IMPORTANT: Never commit config.yaml with real credentials"
    fi
    
    echo ""
}

# Create example test files
create_test_examples() {
    print_header "Creating Test Examples"
    
    # Move test_security_critical.py to tests directory if it exists
    if [ -f "test_security_critical.py" ] && [ ! -f "tests/test_security_critical.py" ]; then
        mv test_security_critical.py tests/
        print_success "Moved test_security_critical.py to tests/"
    fi
    
    # Create __init__.py in tests directory
    if [ ! -f "tests/__init__.py" ]; then
        touch tests/__init__.py
        print_success "Created tests/__init__.py"
    fi
    
    echo ""
}

# Run initial test
run_test_check() {
    print_header "Running Test Environment Check"
    
    # Activate venv if not already active
    if [ -z "$VIRTUAL_ENV" ]; then
        source venv/bin/activate 2>/dev/null || . venv/bin/activate
    fi
    
    print_info "Checking pytest installation..."
    if pytest --version &> /dev/null; then
        print_success "pytest is working"
        pytest --version
    else
        print_error "pytest check failed"
    fi
    
    echo ""
}

# Display next steps
show_next_steps() {
    print_header "Setup Complete! 🎉"
    
    echo -e "${GREEN}Your OPNsense test suite is ready!${NC}"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo ""
    echo "1. Configure your OPNsense connection:"
    echo "   ${BLUE}vim config.yaml${NC}  # Edit with your credentials"
    echo ""
    echo "2. Activate the virtual environment:"
    echo "   ${BLUE}source venv/bin/activate${NC}"
    echo ""
    echo "3. Run your first test:"
    echo "   ${BLUE}pytest -v${NC}"
    echo ""
    echo "4. Generate HTML report:"
    echo "   ${BLUE}pytest --html=report.html --self-contained-html${NC}"
    echo ""
    echo "5. Run only critical tests:"
    echo "   ${BLUE}pytest -m critical${NC}"
    echo ""
    echo -e "${YELLOW}Documentation:${NC}"
    echo "  • README.md - Full documentation"
    echo "  • QUICKSTART.md - Quick start guide"
    echo "  • pytest.ini - Test configuration"
    echo ""
    echo -e "${RED}Security Reminder:${NC}"
    echo "  ⚠ Never commit config.yaml with real credentials"
    echo "  ⚠ Review .gitignore to ensure sensitive files are excluded"
    echo ""
    print_success "Setup completed successfully!"
}

# Main execution
main() {
    clear
    print_header "OPNsense Test Suite Setup"
    echo ""
    
    check_prerequisites
    create_directories
    setup_venv
    install_dependencies
    setup_config
    create_test_examples
    run_test_check
    init_git
    show_next_steps
}

# Run main function
main
