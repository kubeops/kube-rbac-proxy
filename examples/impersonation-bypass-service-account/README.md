# impersonation-bypass-service-account example

This example demonstrates impersonation bypass mode with optional ServiceAccount
verification using TokenReview.

In this setup:

* `kube-rbac-proxy` is started with `--auth-impersonation-bypass`.
* Verification is enabled with:
  * `--auth-impersonation-verify-service-account-namespace=default`
  * `--auth-impersonation-verify-service-account-name=impersonation-client`
* Client requests send `Impersonate-User: alice@example.com`.
* Authorization is evaluated for `alice@example.com` (not for the token subject).

The proxy still performs SubjectAccessReview for the impersonated user. The
bearer token is only accepted for bypass if TokenReview confirms it belongs to
`system:serviceaccount:default:impersonation-client`.

```bash
$ kubectl create -f deployment.yaml
```

The content of this manifest is:

[embedmd]:# (./deployment.yaml)
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-rbac-proxy
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: impersonation-client
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kube-rbac-proxy
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kube-rbac-proxy
subjects:
- kind: ServiceAccount
  name: kube-rbac-proxy
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kube-rbac-proxy
rules:
- apiGroups: ["authentication.k8s.io"]
  resources:
  - tokenreviews
  verbs: ["create"]
- apiGroups: ["authorization.k8s.io"]
  resources:
  - subjectaccessreviews
  verbs: ["create"]
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: kube-rbac-proxy
  name: kube-rbac-proxy
spec:
  ports:
  - name: https
    port: 8443
    targetPort: https
  selector:
    app: kube-rbac-proxy
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-rbac-proxy
data:
  config-file.yaml: |+
    authorization:
      resourceAttributes:
        namespace: default
        apiVersion: v1
        resource: services
        subresource: proxy
        name: kube-rbac-proxy
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kube-rbac-proxy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kube-rbac-proxy
  template:
    metadata:
      labels:
        app: kube-rbac-proxy
    spec:
      securityContext:
        runAsUser: 65532
      serviceAccountName: kube-rbac-proxy
      containers:
      - name: kube-rbac-proxy
        image: quay.io/brancz/kube-rbac-proxy:v0.21.0
        args:
        - "--secure-listen-address=0.0.0.0:8443"
        - "--upstream=http://127.0.0.1:8081/"
        - "--config-file=/etc/kube-rbac-proxy/config-file.yaml"
        - "--auth-token-audiences=kube-rbac-proxy.default.svc"
        - "--auth-impersonation-bypass"
        - "--auth-impersonation-verify-service-account-namespace=default"
        - "--auth-impersonation-verify-service-account-name=impersonation-client"
        - "--logtostderr=true"
        - "--v=10"
        ports:
        - containerPort: 8443
          name: https
        volumeMounts:
        - name: config
          mountPath: /etc/kube-rbac-proxy
        securityContext:
          allowPrivilegeEscalation: false
      - name: prometheus-example-app
        image: quay.io/brancz/prometheus-example-app:v0.5.0
        args:
        - "--bind=127.0.0.1:8081"
      volumes:
      - name: config
        configMap:
          name: kube-rbac-proxy
```

Grant the impersonated user permission to access metrics:

```bash
$ kubectl create -f client-rbac.yaml
```

The content of this manifest is:

[embedmd]:# (./client-rbac.yaml)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kube-rbac-proxy-impersonated-user
rules:
- nonResourceURLs: ["/metrics"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kube-rbac-proxy-impersonated-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kube-rbac-proxy-impersonated-user
subjects:
- kind: User
  name: alice@example.com
```

Run a client job that uses the verified ServiceAccount token and impersonation
header:

```bash
$ kubectl create -f client.yaml
```

The content of this manifest is:

[embedmd]:# (./client.yaml)
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: krp-impersonation-curl
spec:
  template:
    metadata:
      name: krp-impersonation-curl
    spec:
      serviceAccountName: impersonation-client
      restartPolicy: Never
      containers:
      - name: krp-curl
        image: quay.io/brancz/krp-curl:v0.0.2
        command:
        - /bin/sh
        - -c
        - |
          curl -v -s -k \
            -H "Authorization: Bearer $(cat /service-account/token)" \
            -H "Impersonate-User: alice@example.com" \
            https://kube-rbac-proxy.default.svc:8443/metrics
        volumeMounts:
        - name: token-vol
          mountPath: "/service-account"
          readOnly: true
      volumes:
      - name: token-vol
        projected:
          sources:
          - serviceAccountToken:
              audience: kube-rbac-proxy.default.svc
              expirationSeconds: 3600
              path: token
  backoffLimit: 4
```

This request should succeed with HTTP 200 because the token belongs to the
configured ServiceAccount and `alice@example.com` is authorized.

Run a control job with the default ServiceAccount token:

```bash
$ kubectl create -f wrong-client.yaml
```

The content of this manifest is:

[embedmd]:# (./wrong-client.yaml)
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: krp-impersonation-wrong-token
spec:
  template:
    metadata:
      name: krp-impersonation-wrong-token
    spec:
      restartPolicy: Never
      containers:
      - name: krp-curl
        image: quay.io/brancz/krp-curl:v0.0.2
        command:
        - /bin/sh
        - -c
        - |
          curl -v -s -k \
            -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
            -H "Impersonate-User: alice@example.com" \
            https://kube-rbac-proxy.default.svc:8443/metrics
  backoffLimit: 4
```

This request should fail with HTTP 401 because the token does not authenticate
as the configured ServiceAccount.
