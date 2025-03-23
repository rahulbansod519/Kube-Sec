# Kubernetes Security Service Account Setup

This document provides instructions to create a Kubernetes service account with read-only cluster-wide permissions, all within a dedicated namespace (`kube-sec`).

## Prerequisites
- A running Kubernetes cluster
- `kubectl` configured with appropriate permissions

## Steps

### 1. Create the `kube-sec` Namespace
```sh
kubectl create namespace kube-sec
```

### 2. Create the Service Account
```sh
kubectl create serviceaccount security-sa -n kube-sec
```

### 3. Create a ClusterRole with Read-Only Access
```sh
kubectl create clusterrole read-only-role \
  --verb=get,list,watch \
  --resource=pods,deployments,services,nodes
```

### 4. Bind the Role to the Service Account
```sh
kubectl create clusterrolebinding read-only-binding \
  --clusterrole=read-only-role \
  --serviceaccount=kube-sec:security-sa
```

### 5. Generate a Token for the Service Account
```sh
kubectl create token security-sa -n kube-sec
```

### 6. Retrieve the Token
```sh
kubectl get secret $(kubectl get serviceaccount security-sa -n kube-sec -o jsonpath="{.secrets[0].name}") -n kube-sec -o jsonpath="{.data.token}" | base64 --decode
```

### 7. Get the API Server Endpoint
```sh
kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'
```

### 8. Use the Token to Authenticate
You can use this token to authenticate API requests to the Kubernetes cluster with read-only access.

### Notes
- The `security-sa` service account is created in the `kube-sec` namespace.
- It is assigned a `ClusterRole` with `get`, `list`, and `watch` permissions on key resources.
- The token is required to authenticate API requests.

This setup ensures secure, minimal-permission access to the cluster. 🚀

