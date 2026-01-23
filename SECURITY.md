# Security Policy

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

If you discover a security vulnerability in urlp, please report it responsibly by emailing urlp@example.com with:

- Description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact assessment
- Suggested fix (if you have one)

We will acknowledge receipt within 48 hours and provide updates on our progress toward a fix.

## Security Considerations

### URL Validation

urlp provides RFC 3986-compliant URL parsing and validation. However, you should be aware of:

1. **IDNA Processing**: When using IDNA support (`import idna`), hostnames are normalized. Ensure you trust the source of URLs before using them in network requests.

2. **Relative URL References**: The `parse_relative_reference` function does not apply path normalization. Use with caution when handling user-supplied relative URLs.

3. **Port Validation**: urlp validates well-known ports against scheme defaults. Custom schemes may require additional validation in your application.

4. **Fragment Handling**: URL fragments are not transmitted to servers. Do not use fragments for sensitive information.

### Best Practices

- Always validate URLs before using them in network requests
- Use the `strict=True` parameter in `parse_url()` to reject private IP literals in production code
- Keep urlp and its dependencies updated
- Review security advisories from the Python packaging ecosystem

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ Yes |
| 0.0.x | ❌ No |
