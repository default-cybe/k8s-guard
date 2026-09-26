# K8s-Guard: Hardening & Remediation

Run from VM1 (master). The hardened YAML variants are in this folder.

Aligned with the **NSA/CISA Kubernetes Hardening Guide v1.2** (August 2022).
The guide's sections are not numbered; the fixes below cite them by name:
- **Kubernetes Pod security** (pp. 8-13), in particular *Pod security
  enforcement* (p. 12): enforce Pod Security Standards with Pod Security
  Admission.
- **Authentication and authorization** (pp. 22-26), in particular
  *Role-based access control* (pp. 23-26): least-privilege RBAC.

The guide also recommends not auto-mounting service-account tokens in pods
that do not need them (*Protecting Pod service account tokens*, p. 12, and
*Authentication*, p. 22). The lab did **not** apply that setting; see
[Recommended, not applied in the lab](#recommended-not-applied-in-the-lab).

---

## Fix 1: Delete the overly permissive binding
```bash
sudo kubectl delete clusterrolebinding vuln-sa-admin
```
Removes `cluster-admin` from `vuln-sa`. The stolen token keeps only the
permissions Kubernetes gives every authenticated identity by default (API
discovery and reading basic information about itself, through the
`system:basic-user`, `system:discovery` and `system:public-info-viewer`
ClusterRoles). It loses all access to pods, secrets, bindings and other
cluster objects.
(Addresses Vulnerability 2. NSA/CISA: Authentication and authorization.)

## Fix 2: Apply least-privilege RBAC
```bash
sudo kubectl apply -f ~/Desktop/hardened-role.yaml
sudo kubectl apply -f ~/Desktop/hardened-rolebinding.yaml
```
Creates a namespace-scoped Role allowing only `get` and `list` on `pods` in
`vuln-app`, and binds it to `vuln-sa`. The service account can now only view
pods in its own namespace. (NSA/CISA: Authentication and authorization,
Role-based access control.)

Hardened YAML in this folder:
- [`hardened-role.yaml`](./hardened-role.yaml)
- [`hardened-rolebinding.yaml`](./hardened-rolebinding.yaml)

## Fix 3: Apply Pod Security Standards
```bash
sudo kubectl label namespace vuln-app pod-security.kubernetes.io/enforce=restricted --overwrite
```
The `restricted` PSS blocks privileged containers, host namespaces
(`hostPID`, `hostNetwork`), hostPath volumes, running as root, and adding
capabilities other than `NET_BIND_SERVICE`. Pod Security Admission checks every new pod in `vuln-app`
against it, whatever RBAC permissions the requester has, so the `pwned` pod is
rejected at admission even when it is submitted with a cluster-admin token.
(Addresses Vulnerability 3. NSA/CISA: Kubernetes Pod security, Pod security
enforcement.)

This is not a boundary against cluster-admin. A cluster-admin can remove or
change the namespace's `pod-security.kubernetes.io/enforce` label, create the
pod in a namespace that has no enforce label, or change the admission
configuration (for example, add an exemption). It only stops a cluster-admin
who submits the pod to `vuln-app` unchanged, which is why Fix 1 matters.

Enforcement applies when pods are created. Adding the label does not remove
pods that are already running: `kubectl label` prints a warning for each
existing pod that violates the new level, and those pods keep running until
they are deleted. A `pwned` pod created before the label was applied has to
be deleted separately.

Declarative equivalent: [`namespace-hardened.yaml`](./namespace-hardened.yaml)

---

## Recommended, not applied in the lab

**Disable service-account token automount for the webapp.** No manifest in
this repo sets `automountServiceAccountToken`, so the token is still mounted
at `/var/run/secrets/kubernetes.io/serviceaccount/token` after hardening, and
the unfixed LFI can still read it. After Fixes 1 and 2 that token only allows
`get`/`list` on pods in `vuln-app`. The webapp never calls the Kubernetes API,
so it does not need the token at all. Setting this in the pod spec removes it:

```yaml
spec:
  serviceAccountName: vuln-sa
  automountServiceAccountToken: false
```

(It can also be set on the ServiceAccount; if both are set, the pod spec
wins.) This was not part of the lab's hardening steps or grading scripts.

---

## Why all three matter (defense in depth)
- **RBAC fix alone:** Blocks this attacker, but if anyone else gets
  cluster-admin, they can still create privileged pods.
- **PSS alone:** Rejects the privileged pod in `vuln-app`, but the attacker
  still has cluster-admin. With cluster-admin they can remove the label or
  deploy to another namespace, and do other damage.
- **Both together:** The stolen token can only list pods in `vuln-app`, and
  privileged pods are rejected in that namespace.

## Why we don't fix the LFI
The LFI is an application code bug, a developer's job, not a Kubernetes
security fix. The point is: even with the app still vulnerable, proper K8s
security controls limit the blast radius.

---

## Verification (from the lab's grading scripts)
- `grading_script_3.sh` (VM1): checks the RBAC fix: binding deleted + role created.
- `grading_script_4.sh` (VM1): checks PSS: label applied + privileged pod blocked.
