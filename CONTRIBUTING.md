# Contributing to HOMESERVER Keyman Credential Management Suite

Thank you for your interest in contributing to Keyman. This is a **security-critical component** that manages encrypted credential storage for the HOMESERVER platform. We welcome contributions that improve security, reliability, and functionality.

## About This Repository

Keyman provides enterprise-grade credential management using AES-256-CBC encryption with PBKDF2 key derivation. It stores service credentials securely and provides controlled access through ramdisk-based temporary exports.

**Security Impact**: This system protects service credentials for the entire HOMESERVER platform. Security vulnerabilities here could:
- Expose service passwords and API keys
- Compromise multiple HOMESERVER services
- Undermine the entire security model

We review all contributions with security as the top priority.

## Ways to Contribute

### High-Value Contributions

- **Security improvements**: Strengthen encryption, key handling, or access controls
- **Bug fixes**: Address security issues, memory leaks, or edge cases
- **Code quality**: Improve memory safety, error handling, or code clarity
- **Documentation**: Clarify usage, security model, or implementation details
- **Testing**: Validate security properties and edge cases
- **Performance**: Optimize without compromising security

### Security Vulnerability Reporting

**DO NOT** open public issues for security vulnerabilities.

If you discover a security issue:
1. **Email privately**: security@arpaservers.com or owner@arpaservers.com
2. **Include details**: Description, reproduction steps, security impact
3. **Provide PoC**: If possible, include proof-of-concept code
4. **Suggest fixes**: If you have a solution, share it
5. **Wait for response**: We'll acknowledge within 48 hours

We'll coordinate private disclosure and credit you appropriately.

## Getting Started

### Prerequisites

- **C programming**: Experience with secure C code
- **Cryptography**: Understanding of AES, key derivation, secure storage
- **Shell scripting**: Bash proficiency
- **Security mindset**: Think like an attacker
- **Linux systems**: Familiarity with file permissions, ramdisk, systemd

### Repository Setup

1. **Fork the repository** on GitHub:
   ```bash
   git clone git@github.com:YOUR_USERNAME/keyman.git
   cd keyman
   ```

2. **Add upstream remote**:
   ```bash
   git remote add upstream git@github.com:homeserversltd/keyman.git
   ```

3. **Build the project**:
   ```bash
   make
   ```

4. **Study the architecture**: Review README.md and source code

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b security/your-improvement
# or
git checkout -b fix/issue-description
```

### 2. Make Your Changes

**For C code (`keyman-crypto.c`):**
- Memory safety: No buffer overflows, use-after-free, etc.
- Secure cleanup: Zero sensitive data before freeing
- Error handling: Check all return values, fail safely
- No undefined behavior: Follow C standards strictly

**For shell scripts:**
- Input validation: Sanitize all inputs
- Path safety: Use absolute paths, avoid injection
- Secure temp files: Proper permissions and cleanup
- Error handling: Check command return codes

### 3. Test Thoroughly

Security testing is **mandatory**. See [Testing Requirements](#testing-requirements).

### 4. Commit and Push

```bash
git add .
git commit -m "Detailed security-focused message"
git push origin security/your-improvement
```

### 5. Open a Pull Request

Include comprehensive security analysis in your PR.

## Code Quality Standards

### C Code Security Standards

**Memory Safety:**
```c
// GOOD: Bounded operations, secure cleanup
char buffer[256];
strncpy(buffer, input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';
// ... use buffer ...
explicit_bzero(buffer, sizeof(buffer));  // Clear sensitive data
```

```c
// BAD: Unbounded, no cleanup
char buffer[256];
strcpy(buffer, input);  // Buffer overflow risk
// ... use buffer ...
// No cleanup - sensitive data left in memory
```

**Error Handling:**
```c
// GOOD: Check return values, fail safely
if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
    fprintf(stderr, "Encryption initialization failed\n");
    cleanup_crypto();
    return -1;
}
```

**Cryptographic Operations:**
- Use OpenSSL or system crypto libraries (no custom crypto)
- Proper key derivation (PBKDF2 with adequate iterations)
- Secure random number generation (`/dev/urandom`)
- Constant-time operations where applicable

### Shell Script Security Standards

**Input Validation:**
```bash
# GOOD: Validate service name format
if [[ ! "$service_name" =~ ^[a-zA-Z0-9_]+$ ]]; then
    echo "Error: Invalid service name" >&2
    exit 1
fi
```

**Safe File Operations:**
```bash
# GOOD: Secure temp directory with cleanup trap
TEMP_DIR=$(mktemp -d) || exit 1
chmod 700 "$TEMP_DIR"
trap 'rm -rf "$TEMP_DIR"' EXIT
```

**Privilege Handling:**
```bash
# GOOD: Check for root, minimize privilege duration
if [[ $EUID -ne 0 ]]; then
    echo "This script requires root privileges" >&2
    exit 1
fi
```

## Testing Requirements

**Security validation is mandatory for all contributions.**

### Required Testing

1. **Functional testing**: Core operations work correctly
2. **Security testing**: Attempt to break the security model
3. **Memory testing**: No leaks or corruption (use Valgrind)
4. **Permission testing**: Verify file/directory permissions
5. **Integration testing**: Works with HOMESERVER services

### Testing Documentation

Include in your PR:

```markdown
## Security Testing Performed

### Functional Tests
- Created and exported credentials: SUCCESS
- Encrypted/decrypted data correctly: VERIFIED
- Ramdisk auto-cleanup after 15s: VERIFIED

### Security Tests
- Attempted to read credentials without authorization: BLOCKED
- Tested permission bypass: BLOCKED
- Verified secure memory cleanup: PASSED (Valgrind)
- Checked for timing attacks: ANALYZED
- Tested with malicious inputs: HANDLED SAFELY

### Memory Safety
- Valgrind memcheck: NO ERRORS
- AddressSanitizer: NO ISSUES
- No memory leaks detected

### Test Environment
- OS: Debian 12 / Arch Linux
- OpenSSL version: 3.x
- Compiler: GCC 13 with -Wall -Wextra -Werror

### Test Commands
[Include specific test commands used]
```

## Commit Message Guidelines

Security-focused, detailed commit messages:

```
Improve key derivation security in keyman-crypto

Enhanced PBKDF2 key derivation:
- Increased iteration count from 10,000 to 100,000
- Added SHA-256 as hash function (was SHA-1)
- Improved salt generation using /dev/urandom
- Added error checking for all crypto operations

Security rationale:
- Modern GPUs can brute-force 10K iterations quickly
- SHA-1 is deprecated for security purposes
- Proper salt generation prevents rainbow tables
- Defensive error handling prevents undefined behavior

Performance impact: Minimal (~50ms additional latency)
Backward compatibility: Existing keys require re-encryption

Tested with: [security test details]
```

## Pull Request Process

### PR Description Template

```markdown
## Summary
Brief description of changes and motivation.

## Security Impact Analysis
What security properties does this change affect?

## Changes Made
- Specific change 1
- Specific change 2
- Specific change 3

## Security Rationale
Why are these changes secure? What attacks do they prevent?

## Testing Performed
[Use detailed testing template above]

## Backward Compatibility
Does this break existing installations? Migration path?

## Performance Impact
Any performance implications?

## Checklist
- [ ] Code compiles without warnings
- [ ] Memory safety verified (Valgrind)
- [ ] Security testing completed
- [ ] No hardcoded secrets or test credentials
- [ ] Secure defaults maintained
- [ ] Documentation updated
- [ ] Backward compatibility considered
```

### Review Process

1. **Security review**: Deep analysis of security implications
2. **Code review**: Check for memory safety, logic errors
3. **Testing**: Maintainer performs independent testing
4. **Discussion**: Collaborate on any concerns
5. **Approval**: Merge after thorough security validation

Security-critical changes require extra scrutiny and may take longer to review.

## Architecture Understanding

### Two-Tier Encryption

```
skeleton.key (master password)
    ↓
service_suite.key (encrypted with master)
    ↓
individual service credentials (encrypted with service_suite.key)
```

### Components

- **keyman-crypto**: C binary for AES-256-CBC encryption/decryption
- **Shell scripts**: High-level credential management
- **Storage**: `/root/key/` and `/vault/.keys/` with strict permissions
- **Export**: Ramdisk at `/mnt/keyexchange/` with auto-cleanup

### Security Model

- Credentials stored encrypted at rest
- Master password stored plaintext (protected by filesystem permissions)
- Temporary exports to ramdisk only
- 15-second auto-cleanup of exported credentials
- No persistent decrypted storage

## Security Guidelines

### Critical Security Principles

1. **Defense in depth**: Multiple layers of protection
2. **Fail safely**: Errors should deny access, not grant it
3. **Minimal exposure**: Credentials decrypted only when needed
4. **Secure cleanup**: Zero sensitive data immediately after use
5. **Least privilege**: Run with minimum required permissions
6. **No hardcoded secrets**: Ever.

### Common Security Pitfalls

**Avoid:**
- Shell command injection vulnerabilities
- Race conditions in temp file handling
- Memory leaks of sensitive data
- Weak random number generation
- Inadequate key derivation
- Timing side-channels
- Logging sensitive information

## Getting Help

### Resources

- **OpenSSL documentation**: For crypto operations
- **Valgrind manual**: For memory safety testing
- **Keyman README**: Architecture and usage details

### Questions?

- **Open an issue**: General contribution questions
- **Email privately**: Security questions (owner@arpaservers.com)
- **Review code**: Study existing implementation

## Recognition

Security contributors:
- Are credited in the repository and release notes
- Help protect HOMESERVER users' credentials
- Build professional security engineering portfolio
- May receive CVE credit for responsible vulnerability disclosure

## License

This project is licensed under **GPL-3.0**. Contributions are accepted under this license, and no CLA is required.

---

**Thank you for helping secure HOMESERVER credential management!**

Credential security is fundamental to system security. Your careful work protects the entire platform.

*HOMESERVER LLC - Professional Digital Sovereignty Solutions*

