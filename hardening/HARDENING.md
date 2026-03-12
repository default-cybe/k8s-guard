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

## Fix 3: Apply Pod Security Standards
```bash
sudo kubectl label namespace vuln-app pod-security.kubernetes.io/enforce=restricted --overwrite
```
The `restricted` PSS blocks privileged containers, hostPath mounts, running as
root, and other dangerous capabilities. Even with cluster-admin, the privileged
pod would be rejected. (Addresses Vulnerability 3. NSA/CISA Section 4.)

Declarative equivalent: [`namespace-hardened.yaml`](./namespace-hardened.yaml)

---

## Why all three matter (defense in depth)
- **RBAC fix alone:** Blocks this attacker, but if anyone else gets
  cluster-admin, they can still create privileged pods.
- **PSS alone:** Blocks privileged pods, but attacker still has cluster-admin
  for other damage.
- **Both together:** No permissions AND dangerous pod types blocked.

## Why we don't fix the LFI
The LFI is an application code bug, a developer's job, not a Kubernetes
security fix. The point is: even with the app still vulnerable, proper K8s
security controls limit the blast radius.

---

## Verification (from the lab's grading scripts)
- `grading_script_3.sh` (VM1): checks the RBAC fix: binding deleted + role created.
- `grading_script_4.sh` (VM1): checks PSS: label applied + privileged pod blocked.
