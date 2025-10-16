# OctoVault

![OctoVault](docs/assets/logo.png)

OctoVault is a Kubernetes operator that pulls config/secrets from **GitHub** (per repo + path, on an optional **git ref**) and materializes them as native **ConfigMaps** or **Secrets**.  
It also supports external secret sources referenced from your Git-backed `values.yaml`:
- **Key Value** pairs
- **AWS Secrets Manager** (JSON key extraction, stage-aware, cached)
- **AWS Systems Manager Parameter Store** (String/SecureString/StringList, JSON key extraction, cached)

- **CRDs**
    - `OctoRepository` **(cluster-scoped)** — stores GitHub owner/organization and a reference to a namespaced credentials `Secret`. Any namespace can reuse it.
    - `OctoVault` **(namespaced)** — points at a repo/path (and optional `gitRef`), validates & applies data into a target `ConfigMap`/`Secret`.

- **Status you can trust**: `Phase` (`Pending`/`Synced`/`Failed`), `ObservedRevision` (commit SHA), `ResolvedType` (`ConfigMap|Secret`), `AppliedDataHash`, `LastSyncedTime`, and a `Ready` condition.

---

## How it works

1. Create a **GitHub credentials Secret** (PAT) in some namespace (e.g., `octovault-system`, `my-app`).
2. Create a **cluster-scoped** `OctoRepository` pointing at `github.com/<owner>` and referencing that Secret **with namespace+name**.
3. In your workload namespace, create an **OctoVault** referencing the `OctoRepository` by name, plus `repository`, `path` to `values.yaml`, and optional `gitRef` (branch/tag/SHA).
4. The operator:
    - fetches `values.yaml` (and `validator.schema.json` if present) via GitHub API,
    - **optionally** pulls individual keys from **AWS Secrets Manager** (`type: AwsSecretManager`) or **AWS SSM Parameter Store** (`type: AwsParameterStore`),
    - validates and applies as a **ConfigMap** or **Secret**,
    - records status and emits Events.

It keeps the target resource in sync on a timer (`spec.pollInterval`).

###

```mermaid
%% Reference map: how OctoVault and OctoRepository relate

graph LR
  subgraph NS_X["Namespace: team-a"]
    S["Secret: my-org-credentials<br/>label: octovault.it/repository=true<br/>(opt) ann: octovault.it/organization=github.com/my-org"]
  end

  subgraph Cluster["Cluster Scope"]
    OR["OctoRepository: my-org-credentials<br/>scope: Cluster<br/>spec.credentialsRef:<br/>name: my-org-credentials<br/>namespace: team-a<br/>spec.organization: github.com/my-org"]
  end

  subgraph NS_Y["Namespace: app-ns"]
    OV["OctoVault: app-config<br/>spec.octoRepositoryRef.name: my-org-credentials<br/>spec.repository: my-org/my-repo<br/>spec.path: path/to/values.yaml<br/>spec.gitRef: main<br/>spec.targetName: app-config<br/>spec.targetNamespace: app-ns"]
    CM["ConfigMap / Secret<br/>managed-by: octovault<br/>labels:<br/>octovault.it/owner-ns=app-ns<br/>octovault.it/owner-name=app-config<br/>annotation:<br/>octovault.it/owner=app-ns/app-config"]
  end

  OR -- references --> S
  OV -- references by name --> OR
  OV -- reconciles --> CM
```

```mermaid
%% Reconciliation flow from create to applied output

sequenceDiagram
  participant U as User
  participant API as Kubernetes API
  participant RS as RepoSecretReconciler
  participant ORC as OctoRepositoryReconciler
  participant OVC as OctoVaultReconciler
  participant GH as GitHub API

  U->>API: apply Secret (my-org-credentials)<br/>labels: octovault.it/repository=true<br/>(opt) ann: organization=github.com/my-org
  RS->>API: create OctoRepository (Cluster) named "my-org-credentials" (if not present)
  ORC->>API: get Secret (team-a/my-org-credentials)
  ORC->>API: update OctoRepository.status = Synced / Ready

  U->>API: apply OctoVault (app-ns/app-config)<br/>spec.octoRepositoryRef.name=my-org-credentials<br/>spec.repository=my-org/my-repo<br/>spec.path=values.yaml<br/>(opt) spec.gitRef=main
  OVC->>API: get OctoRepository (Cluster)
  OVC->>API: get Secret (team-a/my-org-credentials)
  OVC->>GH: fetch values.yaml at ref (gitRef or default)
  OVC->>API: create/update ConfigMap or Secret (app-ns)<br/>labels: managed-by=octovault, owner-ns/owner-name<br/>annotation: owner=ns/name
  OVC->>API: update OctoVault.status<br/>phase=Synced, resolvedType=ConfigMap|Secret,<br/>observedRevision=<commit SHA>, lastSyncedTime=now
```

---

## CRDs

### OctoRepository (cluster-scoped)

One per GitHub owner/org for the whole cluster. Credentials live in a namespaced `Secret`; the `OctoRepository` is cluster-scoped so any namespace can reuse it.

Example:
```yaml
apiVersion: octovault.it/v1alpha1
kind: OctoRepository
metadata:
  name: my-org
spec:
  organization: "github.com/my-org"
  credentialsRef:
    namespace: octovault-system
    name: my-org-credentials
```
Credentials `Secret`:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-org-credentials
  namespace: octovault-system
type: Opaque
stringData:
  username: "octovault"            # optional (defaults to "octovault")
  password: "<GITHUB_PAT>"         # required
  # passwordEncoding: base64     # optional, if password is base64 text
```

- Label: `octovault.it/repository: "true"`
- Organization: `octovault.it/organization: github.com/my-org` (or `data.organization`)

### OctoVault (namespaced)

Fetches and applies one `values.yaml` as a `ConfigMap` or `Secret` in the **same** (or specified) namespace.
```yaml
apiVersion: octovault.it/v1alpha1
kind: OctoVault
metadata:
  name: app-config
  namespace: demo
spec:
  octoRepositoryRef:
    name: my-org                      # cluster-scoped OctoRepository
  repository: "my-org/my-repo"        # owner/repo
  path: "config/environments/prod.yaml"
  gitRef: "release-2025-09"           # optional (branch/tag/SHA)
  targetName: "app-config"            # ConfigMap/Secret name
  targetNamespace: "demo"             # optional (defaults to this namespace)
  pollInterval: "1m"                  # Go duration (default 1m)
```
Status (abbrev.):
```yaml
status:
  phase: Synced
  observedRevision: 5b32c1f...
  resolvedType: ConfigMap
  appliedDataHash: 4a8d...
  lastSyncedTime: 2025-09-01T03:20:10Z
  conditions:
    - type: Ready
      status: "True"
      reason: "Synced"
      message: "values applied"
```
### `values.yaml` format

#### ConfigMap
```yaml
metadata:
  type: ConfigMap
spec:
  data:
    - key: FOO
      value: "bar"
```
- If `metadata.type` is `ConfigMap`, values become `.data[string]`.
- Only `Text` (default) type is supported.

#### Secret
```yaml
metadata:
  type: Secret
spec:
  data:
    - key: FOO
      value: "bar"                  # type omitted → Text
      # type: Text

    - key: SM_FOO
      type: AwsSecretManager        # pull from AWS Secrets Manager
      name: "prod/app/token"        # secret id/name/arn acceptable
      jsonKey: "foo.bar"            # optional dot-path into JSON. Omit for whole value.

    - key: PS_FOO                   # from AWS SSM Parameter Store
      type: AwsParameterStore
      name: "/prod/app/param"       # parameter name (supporting path-style)
      withDecryption: true          # set true for SecureString
      jsonKey: "nested.key"         # optional dot-path into JSON. Omit for whole value.
```

- If `metadata.type` is `Secret`, values become `.data[bytes]` (`Opaque`).
- Only Secret types `Text` (default), `AwsSecretManager`, and `AwsParameterStore` are supported.

> Notes
>
> **AwsSecretManager**
> 
> -	Auth via your controller ServiceAccount (IRSA/web-identity/etc.).
> 
> -	jsonKey extracts a nested field from a JSON SecretString; non-string nodes are serialized to JSON.
> 
> -	The provider surfaces VersionId and VersionStages internally and caches results with a TTL.
> 
> **AwsParameterStore**
> 
> - Supports String, SecureString, and StringList.
> 
> -	Use withDecryption: true when the type is SecureString.
> 
> -	If the parameter value is JSON, you may extract a field via jsonKey. Non-string nodes are serialized to JSON.
> 
> -	StringList is returned as-is (comma-separated); OctoVault does not split it automatically.
>

---

## Install

### Helm

The chart (`charts/octovault-operator`) includes CRDs in its `crds/` folder; Helm will install them automatically (Helm ≥3.2).

```
helm upgrade --install --create-namespace --namespace=octovault-system \
  --values values.yaml octovault-system oci://ghcr.io/octovault/octovault
```

Common values:
```yaml
image:
  repository: ghcr.io/octovault/octovault
  tag: v0.0.1
controller:
  probes:
    healthz: ":8081"
  metrics:
    enabled: true
    secure: true
    port: 8443
  enableHTTP2: false
  env:
    OVO_OCTOREPO_POLL_INTERVAL: "3m"
    OVO_GIT_API_URL: ""      # default https://api.github.com
    OVO_GIT_REF: ""          # global default ref (fallback)
    OVO_AWS_REGION: ""       # empty → AWS SDK default chain (IRSA)
    OVO_AWS_SM_TTL: "3m"     # AWS SM cache TTL. Default 1m
    OVO_AWS_PS_TTL: "3m"     # AWS Parameter Store cache TTL. Default 1m
```
### Manual CRDs

If you prefer manual steps:
```bash
kubectl apply -f config/crd/bases/      # CRDs
# then deploy controller manifests or Helm
```
---

## Configuration & environment

| Env var                      | Purpose                                                       | Default                  |
|------------------------------|---------------------------------------------------------------|--------------------------|
| `OVO_OCTOREPO_POLL_INTERVAL` | Requeue period for `OctoRepository` reconciler (e.g. `1m`)    | `1m`                     |
| `OVO_GIT_API_URL`            | GitHub API base (`https://api.github.com` or GHES URL)        | `https://api.github.com` |
| `OVO_GIT_REF`                | **Global** default git ref if `OctoVault.spec.gitRef` is empty | *(none)*                 |
| `OVO_AWS_REGION`             | Region override for AWS SM (empty → SDK default/IRSA)         | *(auto)*                 |
| `OVO_AWS_SM_TTL`             | AWS SM cache TTL (Go duration)                                | `1m`                     |
| `OVO_AWS_PS_TTL`             | AWS Parameter Store cache TTL (Go duration)                   | `1m`                     |

---

## Permissions & security

- **GitHub PAT** in a K8s `Secret`.
    - Scopes:
        - public repos only → PAT optional,
        - private repo read → `repo`,
        - sometimes `read:org` as org policy requires.
- **AWS SM** via IRSA/web-identity. Grant `secretsmanager:GetSecretValue` for referenced secrets.
- **AWS PS** via IRSA/web-identity. Grant `secretsmanager:GetParameter` for referenced values.
- Operator writes into the target namespace and sets `ownerReferences` to the `OctoVault` for GC.

---

## Observability

- Conditions and rich Status on both CRDs.
- Kubernetes Events for error/success paths.
- Prometheus metrics endpoint (HTTP/HTTPS) with optional authz.

---

## Development

Repo layout:

    api/v1alpha1/                 # CRD Go types
    internal/controller/          # reconcilers
    internal/github/              # GitHub fetcher
    internal/awssm/               # AWS Secrets Manager provider
    charts/octovault-operator/    # Helm chart (includes CRDs)

Make targets:

    make manifests     # generate CRDs/RBAC
    make generate      # deepcopy, etc.
    make build         # manager binary
    make run           # run locally against current kubeconfig
    make test          # unit tests via envtest
    make build-installer

Tests cover controllers (`OctoVault`, `OctoRepository`), the GitHub fetcher (content + commit APIs, path/encoding, ref pinning), and the AWS SM provider (jsonKey extraction, caching, error mapping).

---

## Contributing

Issues and PRs are welcome. Please run `make lint` and `make test` before opening a PR. For larger changes, open an issue to discuss design/UX first.

### dev-whoan [![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-orange?logo=buy-me-a-coffee)](https://www.buymeacoffee.com/dev.whoan)

- [GitHub](https://github.com/dev-whoan)

---
