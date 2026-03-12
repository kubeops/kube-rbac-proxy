#!/usr/bin/env bash

sed -e "s/KUBE_RBAC_PROXY_VERSION/`cat VERSION`/g" scripts/templates/non-resource-url-deployment.yaml > examples/non-resource-url/deployment.yaml
sed -e "s/KUBE_RBAC_PROXY_VERSION/`cat VERSION`/g" scripts/templates/non-resource-url-token-request-deployment.yaml > examples/non-resource-url-token-request/deployment.yaml
sed -e "s/KUBE_RBAC_PROXY_VERSION/`cat VERSION`/g" scripts/templates/impersonation-bypass-service-account-deployment.yaml > examples/impersonation-bypass-service-account/deployment.yaml
sed -e "s/KUBE_RBAC_PROXY_VERSION/`cat VERSION`/g" scripts/templates/resource-attributes-deployment.yaml > examples/resource-attributes/deployment.yaml
sed -e "s/KUBE_RBAC_PROXY_VERSION/`cat VERSION`/g" scripts/templates/rewrites-deployment.yaml > examples/rewrites/deployment.yaml
sed -e "s/KUBE_RBAC_PROXY_VERSION/`cat VERSION`/g" scripts/templates/oidc-deployment.yaml > examples/oidc/deployment.yaml
