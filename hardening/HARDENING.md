# K8s-Guard: Hardening & Remediation

Run from VM1 (master). The hardened YAML variants are in this folder.

Aligned with the **NSA/CISA Kubernetes Hardening Guide v1.2** (August 2022):
- **Section 4**: Enforce Pod Security Standards
- **Section 5**: Least-privilege RBAC, don't auto-mount service account tokens

---

## Fix 1: Delete the overly permissive binding
```bash
sudo kubectl delete clusterrolebinding vuln-sa-admin
```
Removes `cluster-admin` from `vuln-sa`. The stolen token now has zero
permissions. (Addresses Vulnerability 2. NSA/CISA Section 5.)

## Fix 2: Apply least-privilege RBAC
```bash
sudo kubectl apply -f ~/Desktop/hardened-role.yaml
sudo kubectl apply -f ~/Desktop/hardened-rolebinding.yaml
```
Creates a namespace-scoped Role allowing only `get` and `list` on `pods` in
`vuln-app`, and binds it to `vuln-sa`. The service account can now only view
pods in its own namespace. (NSA/CISA Section 5.)

Hardened YAML in this folder:
- [`hardened-role.yaml`](./hardened-role.yaml)
- [`hardened-rolebinding.yaml`](./hardened-rolebinding.yaml)

