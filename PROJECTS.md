# Kubauth projects

Kubauth system is made of several projects:

## kubauth: 

The main project

- image:  
  - quay.io/kubauth/exec/kubauth-server
- helm chart:
  - kubauth-server: The OIDC server deployment
  - kubauth-grant: A chart to define user, groups, groupBindings, roleBindings, clusterRoleBindings

## kubauth-kit: 

Kubauth Kubernetes integration tools

- image: 
  - quay.io/kubauth/exec/kubauth-kit
- helm chart: 
  - kubauth-apiserver: Api server configurator
  - kubauth-kubeconfig: An server to automate client kubeconfig automation

## kc

A client CLI tool to:

- Configure local kubeconfig file
- User login, logout, whoami, ...
- Manage jwt token 
- ...
