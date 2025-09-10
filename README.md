# KubAuth

A Kubernetes-native OpenID Connect (OIDC) Identity Provider that runs entirely on Kubernetes resources.

## Overview

KubAuth is a fully-featured OIDC identity provider designed for Kubernetes environments. It stores users, groups, clients, and sessions as native Kubernetes resources, providing a scalable and cloud-native authentication solution.

### Key Features

- **🔐 Full OIDC Compliance**: Supports all standard OIDC flows including Authorization Code, Resource Owner Password Credentials (ROPC), and Client Credentials
- **🎯 PKCE Support**: Complete Proof Key for Code Exchange (PKCE) implementation with configurable enforcement
- **🗄️ Kubernetes-Native Storage**: All data stored as Kubernetes Custom Resources (CRDs)
- **🔄 SSO Capabilities**: Cross-application Single Sign-On with persistent sessions
- **👥 User & Group Management**: Fine-grained user authentication and group-based authorization
- **🛡️ Security First**: bcrypt password hashing, JWT signing with persistent keys, secure session management
- **📊 Production Ready**: Metrics, health checks, webhooks, and Helm chart deployment

## Architecture

KubAuth consists of two main components:

1. **OIDC Server**: Handles OpenID Connect authentication flows
2. **User Database**: Manages users, groups, and group bindings

Both components can run as separate pods or together in a single deployment.

## Installation

### Prerequisites

- Kubernetes cluster (v1.20+)
- Helm 3.x
- cert-manager (for TLS certificates)

### Quick Start with Helm

```bash
# Install with basic configuration using OCI chart
helm install kubauth oci://quay.io/kubauth/charts/kubauth \
  --version 0.1.1-snapshot \
  --set oidc.issuer="https://auth.example.com" \
  --set oidc.ingress.host="auth.example.com" \
  --set oidc.postLogoutURL="https://example.com"
```

### Production Installation

```bash
# Create a values file
cat > values.yaml << EOF
oidc:
  issuer: "https://auth.example.com"
  postLogoutURL: "https://example.com"
  ingress:
    enabled: true
    host: "auth.example.com"
  server:
    certificateIssuer: "letsencrypt-prod"
  enforcePKCE: true
  allowPasswordGrant: false

data:
  enabled: true
  oidc:
    oidcClients:
      - name: "my-app"
        spec:
          id: "my-app-client"
          hashedSecret: "$2a$12$..."  # Generate using kc hash command
          redirectURIs:
            - "https://my-app.example.com/callback"
          grantTypes: ["authorization_code", "refresh_token"]
          responseTypes: ["code"]
          scopes: ["openid", "profile", "email", "groups"]
          displayName: "My Application"
          entryURL: "https://my-app.example.com"
EOF

helm install kubauth oci://quay.io/kubauth/charts/kubauth --version 0.1.1-snapshot -f values.yaml
```

## Configuration

### Core Configuration

Key configuration options in `values.yaml`:

```yaml
oidc:
  # Required: OIDC issuer URL
  issuer: "https://auth.example.com"
  
  # Required: Where to redirect after logout
  postLogoutURL: "https://example.com"
  
  # Security settings
  enforcePKCE: true              # Enforce PKCE for all clients
  allowPasswordGrant: false      # Allow password grant type
  
  # Server configuration
  server:
    tls: true
    bindPort: 8102
    certificateIssuer: "letsencrypt-prod"
  
  # Ingress configuration
  ingress:
    enabled: true
    class: "nginx"
    host: "auth.example.com"
```

### Advanced Configuration

```yaml
oidc:
  # Session management
  sso:
    sticky: true
    lifeTime: "8h"
    cleanupPeriod: "5m"
  
  # Logging and debugging
  logger:
    mode: "json"
    level: "info"
  dumpExchanges: 0
  
  # Performance tuning
  resources:
    requests:
      cpu: "100m"
      memory: "512Mi"
    limits:
      cpu: "500m"
      memory: "1024Mi"
```

## User and Client Management

### Managing Users

Users are defined as Kubernetes resources:

```yaml
apiVersion: kubauth.kubotal.io/v1alpha1
kind: User
metadata:
  name: john
  namespace: kubauth-users
spec:
  commonNames:
    - "John Doe"
  emails:
    - "john@example.com"
  passwordHash: "$2a$12$iw.ywr.87sGXAkK1HSIU6OIBTyVs4/at1T7I1ueLPPt9CPxOpkmbW"
  claims:
    job: "developer"
    department: "engineering"
  disabled: false
```

### Managing Groups

```yaml
apiVersion: kubauth.kubotal.io/v1alpha1
kind: Group
metadata:
  name: developers
  namespace: kubauth-users
spec:
  comment: "Development team"
  claims:
    access_level: "standard"
```

### Group Bindings

```yaml
apiVersion: kubauth.kubotal.io/v1alpha1
kind: GroupBinding
metadata:
  name: john-developers
  namespace: kubauth-users
spec:
  user: "john"
  group: "developers"
```

### OIDC Clients

```yaml
apiVersion: kubauth.kubotal.io/v1alpha1
kind: OidcClient
metadata:
  name: my-app
  namespace: kubauth-oidc
spec:
  hashedSecret: "$2a$12$..."  # Use 'kc hash' to generate
  redirectURIs:
    - "https://my-app.example.com/callback"
  grantTypes:
    - "authorization_code"
    - "refresh_token"
  responseTypes:
    - "code"
  scopes:
    - "openid"
    - "profile"
    - "email"
    - "groups"
  displayName: "My Application"
  description: "Main company application"
  entryURL: "https://my-app.example.com"
  public: false
  accessTokenLifespan: "1h"
  refreshTokenLifespan: "24h"
  idTokenLifespan: "1h"
```

## Testing and Development

### KubAuth CLI Tool

Use the [kc CLI tool](https://github.com/kubauth/kc) for testing and password generation:

```bash
# Install kc
go install github.com/kubauth/kc@latest

# Generate password hash
kc hash --password "mypassword"

# Generate client secret hash
kc hash --secret "my-client-secret"

# Test OIDC flow
kc ui --issuer https://auth.example.com --client-id my-app --pkce

# Test password grant
kc noui --issuer https://auth.example.com --client-id my-app \
        --username john --password mypassword
```

### Local Development

```bash
# Clone the repository
git clone https://github.com/kubauth/kubauth.git
cd kubauth

# Build the binary
make build

# Run locally (requires kubeconfig)
./bin/kubauth oidc \
  --issuer "http://localhost:8101" \
  --postLogoutURL "http://localhost:3000" \
  --oidcClientNamespace "kubauth-oidc" \
  --ssoNamespace "kubauth-sso" \
  --jwtKeySecretNamespace "kubauth-system"
```

## API Endpoints

KubAuth implements the full OIDC specification:

### Standard OIDC Endpoints

- `GET /.well-known/openid-configuration` - OIDC discovery
- `GET /oauth2/auth` - Authorization endpoint
- `POST /oauth2/token` - Token endpoint
- `GET /oauth2/userinfo` - UserInfo endpoint
- `GET /oauth2/jwks` - JSON Web Key Set
- `POST /oauth2/introspect` - Token introspection
- `POST /oauth2/logout` - Logout endpoint

### Additional Endpoints

- `GET /` - Application portal (lists configured clients)
- `GET /oauth2/login` - Login page
- `GET /health` - Health check

## Grant Types and Flows

### Supported Grant Types

- **Authorization Code** (recommended): Standard OIDC flow with optional PKCE
- **Resource Owner Password Credentials**: Direct username/password authentication
- **Client Credentials**: Service-to-service authentication
- **Refresh Token**: Token renewal

### PKCE Support

KubAuth fully supports PKCE (RFC 7636):

```yaml
oidc:
  enforcePKCE: true          # Require PKCE for all authorization code flows
  allowPKCEPlain: false      # Only allow S256 challenge method
```

## Security Considerations

### Password Security

- Uses bcrypt for password hashing with configurable cost
- Supports password policy enforcement via admission webhooks
- Secure session management with configurable timeouts

### JWT Security

- RSA-2048 key pairs for JWT signing
- Persistent key storage in Kubernetes secrets
- Configurable token lifespans per client
- Proper audience (`aud`) and authorized party (`azp`) claims

### Network Security

- TLS/HTTPS enforcement
- Network policies for pod-to-pod communication
- Configurable CORS headers
- Rate limiting and DDoS protection

## Monitoring and Observability

### Metrics

Enable Prometheus metrics:

```yaml
oidc:
  metrics:
    enabled: true
    serviceMonitor:
      enabled: true
```

### Health Checks

- `/health` endpoint for readiness/liveness probes
- Automatic cleanup of expired sessions
- Resource validation webhooks

### Logging

Structured logging with configurable levels:

```yaml
oidc:
  logger:
    mode: "json"        # json or dev
    level: "info"       # debug, info, warn, error
  dumpExchanges: 1      # HTTP request/response logging
```

## Troubleshooting

### Common Issues

1. **PKCE Validation Errors**
   ```
   The PKCE code challenge did not match the code verifier
   ```
   - Ensure client implements PKCE correctly (SHA256 hash of verifier)
   - Check `enforcePKCE` setting in configuration

2. **Certificate Issues**
   ```
   x509: certificate signed by unknown authority
   ```
   - Verify cert-manager is installed and configured
   - Check certificate issuer configuration

3. **Permission Errors**
   ```
   oidcclients.kubauth.kubotal.io is forbidden
   ```
   - Verify RBAC permissions for service account
   - Check namespace configuration

### Debug Mode

Enable debug logging and request tracing:

```yaml
oidc:
  logger:
    level: "debug"
  dumpExchanges: 3      # Full HTTP dumps
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Environment

```bash
# Setup development environment
make dev-setup

# Run tests
make test

# Generate CRDs
make generate

# Build and run locally
make build && ./bin/kubauth --help
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Links

- [OIDC Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [kc CLI Tool](https://github.com/kubauth/kc)
- [Helm Chart OCI Image](https://quay.io/repository/kubauth/charts/kubauth)

---

For support and questions, please open an issue in the [GitHub repository](https://github.com/kubauth/kubauth).