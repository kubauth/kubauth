
# 🚧 **WARNING: PROJECT UNDER DEVELOPMENT** 🚧

> This project is currently under active development and is **not yet operational**.  
> Do **not** use in production. Features and APIs may change at any time.

# Kubauth

A Kubernetes-native OpenID Connect (OIDC) Identity Provider.

## Overview

KubAuth is a fully-featured OIDC identity provider designed for Kubernetes environments.

It stores users, groups, clients, and sessions as native Kubernetes resources, providing a scalable and cloud-native authentication solution.

Can be fully autonomous, hosting its own User database or acting as a relay for external identity provider such as LDAP.

## Key Features

- **OIDC Compliance**: Supports standard OIDC flows including Authorization Code, and Resource Owner Password Credentials (ROPC)
- **PKCE Support**: Complete Proof Key for Code Exchange (PKCE) implementation with configurable enforcement
- **Kubernetes-Native Storage**: All data stored as Kubernetes Custom Resources (CRDs). NO DATABASE
- **SSO Capabilities**: Cross-application Single Sign-On with persistent sessions
- **User & Group Management**: Fine-grained user authentication and group-based authorization.
    - Claims can be defined at users or group level.
    - User profile can be built from several identity sources
- **Security First**: bcrypt password hashing, JWT signing with persistent keys, secure session management
- **Production Ready**: Health checks, webhooks, and Helm chart deployment

## Kubauth components

Kubauth is made from several subprojects:

- **kubauth**: The main project, the OIDC server with all its connectors.
- **kc**: A companion CLI tool.
- Two subprojects aimed to authenticate `kubectl` users with OIDC.
    - **kubauth-apiserver**: A kubernetes configuration tools to automate the k8s `apiserver` configuration.
    - **kubauth-kubeconfig**: A tool to automate the `kubectl` client configuration.

## Documentation

You will find Kubauth documentation [here](https://kubauth.github.io/kubauth-doc/)