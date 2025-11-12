# Go Secure Coding Practices

This repository contains examples and implementations of secure coding practices for Go applications, following the [OWASP Go Secure Coding Practices Guide](https://github.com/OWASP/Go-SCP).

## Table of Contents

- [Introduction](#introduction)
- [Input Validation](#input-validation)
- [Output Encoding](#output-encoding)
- [Authentication and Password Management](#authentication-and-password-management)
- [Session Management](#session-management)
- [Access Control](#access-control)
- [Cryptographic Practices](#cryptographic-practices)
- [Error Handling and Logging](#error-handling-and-logging)
- [Data Protection](#data-protection)
- [Communication Security](#communication-security)
- [System Configuration](#system-configuration)
- [Database Security](#database-security)
- [File Management](#file-management)
- [Memory Management](#memory-management)
- [General Coding Practices](#general-coding-practices)
- [Resources](#resources)

## Introduction

This guide implements secure coding practices for Go web applications based on the OWASP Secure Coding Practices Quick Reference Guide. The goal is to help developers avoid common security vulnerabilities while building robust Go applications.

### Target Audience

- Go developers building web applications
- Security-conscious programmers
- Developers transitioning from other languages to Go
- Anyone looking to improve their secure coding skills

## Input Validation

**Location:** `input-validation/`

Input validation is the first line of defense against many security vulnerabilities including SQL injection, XSS, command injection, and path traversal attacks.

### Key Principles

1. **Validate all input** - Never trust user input
2. **Use allow-lists over deny-lists** - Define what is acceptable rather than what is not
3. **Validate on the server-side** - Client-side validation can be bypassed
4. **Canonicalize before validation** - Handle URL encoding, Unicode normalization, etc.

### Implementation Examples

#### Sanitize Input

```go
func SanitizeInput(input string) string {
    // Handle URL encoding
    input, _ = url.QueryUnescape(input)

    // Remove null bytes
    input = strings.ReplaceAll(input, "\x00", "")

    // Ensure valid UTF-8
    if !utf8.ValidString(input) {
        input = strings.ToValidUTF8(input, "")
    }

    // Remove control characters
    input = strings.Map(func(r rune) rune {
        if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
            return -1
        }
        return r
    }, input)

    return input
}
```

#### Validate Using Allow-lists

```go
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-.]{2,31}$`)

func ValidateUsername(username string) error {
    username = SanitizeInput(username)
    if !usernameRegex.MatchString(username) {
        return errors.New("invalid username format")
    }
    return nil
}
```

#### Email Validation

```go
func ValidateEmail(email string) error {
    email = SanitizeInput(email)
    addr, err := mail.ParseAddress(email)
    if err != nil {
        return errors.New("invalid email format")
    }
    // Additional validation
    if len(addr.Address) > 254 {
        return errors.New("email too long")
    }
    return nil
}
```

#### Numeric Range Validation

```go
func ValidateAge(age int) error {
    if age < 0 || age > 150 {
        return errors.New("age must be between 0 and 150")
    }
    return nil
}
```

### Best Practices

- ✅ Validate data type, length, format, and range
- ✅ Use strong typing where possible
- ✅ Validate file uploads (type, size, content)
- ✅ Sanitize input before validation
- ✅ Use parameterized queries for database operations
- ❌ Don't rely solely on client-side validation
- ❌ Don't use blacklists for validation

## Output Encoding

Proper output encoding prevents XSS and injection attacks by ensuring data is treated as data, not executable code.

### HTML Encoding

```go
import "html/template"

func SafeHTMLOutput(userInput string) string {
    return template.HTMLEscapeString(userInput)
}
```

### JavaScript Encoding

```go
func SafeJSOutput(userInput string) string {
    return template.JSEscapeString(userInput)
}
```

### URL Encoding

```go
import "net/url"

func SafeURLParameter(param string) string {
    return url.QueryEscape(param)
}
```

### Best Practices

- ✅ Use context-aware encoding (HTML, JavaScript, URL, CSS)
- ✅ Use Go's `html/template` package for HTML rendering
- ✅ Encode all untrusted data before output
- ✅ Use appropriate content-type headers

## Authentication and Password Management

### Password Hashing

```go
import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) (string, error) {
    // Use appropriate cost factor (10-12 for bcrypt)
    hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
    if err != nil {
        return "", err
    }
    return string(hash), nil
}

func VerifyPassword(hashedPassword, password string) error {
    return bcrypt.CompareHashAndPassword(
        []byte(hashedPassword),
        []byte(password),
    )
}
```

### Best Practices

- ✅ Use bcrypt, scrypt, or Argon2 for password hashing
- ✅ Implement strong password policies
- ✅ Use multi-factor authentication where possible
- ✅ Implement account lockout after failed attempts
- ✅ Use secure password reset mechanisms
- ❌ Never store passwords in plain text
- ❌ Don't use weak hashing algorithms (MD5, SHA1)

## Session Management

### Secure Session Configuration

```go
import "github.com/gorilla/sessions"

func NewSecureStore(secretKey []byte) *sessions.CookieStore {
    store := sessions.NewCookieStore(secretKey)
    store.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   3600, // 1 hour
        HttpOnly: true,
        Secure:   true, // HTTPS only
        SameSite: http.SameSiteStrictMode,
    }
    return store
}
```

### Best Practices

- ✅ Generate strong session IDs (cryptographically random)
- ✅ Set appropriate session timeouts
- ✅ Use HttpOnly and Secure flags on cookies
- ✅ Regenerate session ID after login
- ✅ Implement proper session invalidation on logout
- ✅ Use SameSite cookie attribute

## Access Control

### Middleware for Authorization

```go
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        session, _ := store.Get(r, "session-name")

        if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
    })
}
```

### Best Practices

- ✅ Deny by default
- ✅ Implement least privilege principle
- ✅ Check authorization on every request
- ✅ Use role-based access control (RBAC)
- ✅ Protect sensitive resources
- ❌ Don't rely on client-side access control

## Cryptographic Practices

### Generating Random Values

```go
import "crypto/rand"

func GenerateRandomBytes(n int) ([]byte, error) {
    b := make([]byte, n)
    _, err := rand.Read(b)
    if err != nil {
        return nil, err
    }
    return b, nil
}
```

### Secure Random String

```go
func GenerateRandomString(length int) (string, error) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b := make([]byte, length)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    for i := range b {
        b[i] = charset[int(b[i])%len(charset)]
    }
    return string(b), nil
}
```

### Best Practices

- ✅ Use `crypto/rand` for random number generation
- ✅ Use established cryptographic libraries
- ✅ Keep cryptographic keys secure
- ✅ Use TLS 1.2+ for transport security
- ❌ Don't implement your own cryptographic algorithms
- ❌ Don't use `math/rand` for security purposes

## Error Handling and Logging

### Secure Error Handling

```go
func HandleError(w http.ResponseWriter, err error, userMsg string) {
    // Log detailed error server-side
    log.Printf("Error: %v", err)

    // Return generic message to user
    http.Error(w, userMsg, http.StatusInternalServerError)
}
```

### Structured Logging

```go
import "log/slog"

func LogSecurityEvent(event string, details map[string]any) {
    slog.Info("security_event",
        "event", event,
        "details", details,
        "timestamp", time.Now(),
    )
}
```

### Best Practices

- ✅ Log all authentication attempts
- ✅ Log access control failures
- ✅ Log input validation failures
- ✅ Use structured logging
- ✅ Protect log files from unauthorized access
- ❌ Don't log sensitive data (passwords, tokens, PII)
- ❌ Don't expose stack traces to users

## Data Protection

### Encrypting Sensitive Data

```go
import "crypto/aes"
import "crypto/cipher"

func Encrypt(plaintext, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }

    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}
```

### Best Practices

- ✅ Encrypt sensitive data at rest
- ✅ Use strong encryption algorithms (AES-256)
- ✅ Protect encryption keys
- ✅ Use secure key management systems
- ✅ Implement secure data deletion

## Communication Security

### HTTPS Configuration

```go
func StartSecureServer(addr string, handler http.Handler) error {
    cfg := &tls.Config{
        MinVersion:               tls.VersionTLS12,
        CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
        },
    }

    srv := &http.Server{
        Addr:         addr,
        Handler:      handler,
        TLSConfig:    cfg,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    return srv.ListenAndServeTLS("cert.pem", "key.pem")
}
```

### Best Practices

- ✅ Use TLS 1.2 or higher
- ✅ Use strong cipher suites
- ✅ Implement HTTP Strict Transport Security (HSTS)
- ✅ Validate SSL/TLS certificates
- ✅ Use secure HTTP headers

## Database Security

### Parameterized Queries

```go
func GetUserByEmail(db *sql.DB, email string) (*User, error) {
    var user User
    query := "SELECT id, username, email FROM users WHERE email = ?"
    err := db.QueryRow(query, email).Scan(&user.ID, &user.Username, &user.Email)
    if err != nil {
        return nil, err
    }
    return &user, nil
}
```

### Best Practices

- ✅ Always use parameterized queries
- ✅ Use least privilege database accounts
- ✅ Encrypt database connections
- ✅ Validate input before database operations
- ❌ Never concatenate user input into SQL queries

## File Management

### Safe File Upload

```go
func ValidateFileUpload(file multipart.File, header *multipart.FileHeader) error {
    // Check file size
    if header.Size > 10*1024*1024 { // 10MB
        return errors.New("file too large")
    }

    // Check file extension
    allowedExtensions := map[string]bool{
        ".jpg": true, ".jpeg": true, ".png": true, ".pdf": true,
    }
    ext := strings.ToLower(filepath.Ext(header.Filename))
    if !allowedExtensions[ext] {
        return errors.New("file type not allowed")
    }

    // Verify file content matches extension
    buffer := make([]byte, 512)
    _, err := file.Read(buffer)
    if err != nil {
        return err
    }
    contentType := http.DetectContentType(buffer)
    file.Seek(0, 0) // Reset file pointer

    // Validate content type
    // ... additional validation

    return nil
}
```

### Best Practices

- ✅ Validate file type, size, and content
- ✅ Use allow-lists for file extensions
- ✅ Store files outside web root
- ✅ Generate random filenames
- ✅ Scan uploaded files for malware
- ❌ Don't trust file extensions alone

## Memory Management

### Prevent Memory Leaks

```go
// Use defer for cleanup
func ProcessData() error {
    file, err := os.Open("data.txt")
    if err != nil {
        return err
    }
    defer file.Close()

    // Process file...
    return nil
}
```

### Best Practices

- ✅ Use `defer` for resource cleanup
- ✅ Close database connections properly
- ✅ Use context for cancellation and timeouts
- ✅ Be careful with goroutine leaks
- ✅ Use sync.Pool for frequently allocated objects

## General Coding Practices

### Security Headers

```go
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        w.Header().Set("Content-Security-Policy", "default-src 'self'")
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        next.ServeHTTP(w, r)
    })
}
```

### Rate Limiting

```go
import "golang.org/x/time/rate"

func RateLimitMiddleware(limiter *rate.Limiter) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if !limiter.Allow() {
                http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

### Best Practices

- ✅ Keep dependencies up to date
- ✅ Use static analysis tools (gosec, staticcheck)
- ✅ Implement proper error handling
- ✅ Use security linters
- ✅ Follow Go idioms and best practices
- ✅ Conduct security code reviews
- ✅ Implement defense in depth

## Resources

### OWASP Resources

- [OWASP Go Secure Coding Practices Guide](https://github.com/OWASP/Go-SCP)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### Go Security Tools

- [gosec](https://github.com/securego/gosec) - Go security checker
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) - Vulnerability scanner
- [staticcheck](https://staticcheck.io/) - Static analysis tool

### Recommended Packages

- `golang.org/x/crypto` - Cryptographic packages
- `github.com/gorilla/sessions` - Session management
- `github.com/gorilla/csrf` - CSRF protection
- `golang.org/x/time/rate` - Rate limiting

### Further Reading

- [Go Security Best Practices](https://go.dev/doc/security/)
- [Effective Go](https://go.dev/doc/effective_go)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)

## Project Structure

This repository is organized by security topic:

```
secure-coding/
├── input-validation/      # Input validation examples
│   ├── main.go
│   └── utils/
│       └── validator.go
├── authentication/        # Auth and password management (coming soon)
├── cryptography/         # Cryptographic practices (coming soon)
├── database/             # Database security (coming soon)
└── README.md             # This file
```

## Contributing

Contributions are welcome! Please ensure:

1. Code follows Go best practices
2. Security principles are properly implemented
3. Examples are well-documented
4. Tests are included

## License

This project follows the OWASP Go-SCP guide, which is released under the Creative Commons Attribution-ShareAlike 4.0 International license (CC BY-SA 4.0).

## Disclaimer

These examples are for educational purposes. Always conduct thorough security testing and consider your specific use case when implementing security controls.

---

**Remember:** Security is not a one-time task but a continuous process. Stay updated with the latest security advisories and best practices.
