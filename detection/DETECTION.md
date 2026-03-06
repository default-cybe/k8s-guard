# K8s-Guard: Detection & Investigation

Detection happens on VM4 (Security Onion), from the defender's side.

## Data flow
```
VM1 (K8s Audit Logs) ──Filebeat──> VM4 (Security Onion / Elasticsearch)
VM2 (Falco Alerts)   ──Filebeat──> VM4 (Security Onion / Elasticsearch)
```

Two complementary telemetry sources:
- **Kubernetes audit logs**: API-level activity (who created what pod, from
  where). Config: [`k3s-audit-config.yaml`](./k3s-audit-config.yaml),
  shipped by [`filebeat-vm1-audit.yml`](./filebeat-vm1-audit.yml) into the
  `k8s-audit-*` index.
- **Falco alerts**: runtime syscall activity *inside* the container (eBPF).
  Shipped by [`filebeat-vm2-falco.yml`](./filebeat-vm2-falco.yml) into the
  `falco-alerts-*` index.

> **Why both are needed.** Audit logs show WHO did WHAT at the API level
> (created a pod, exec'd into it). Falco shows WHAT HAPPENED INSIDE the
> container (read `/etc/shadow`). Without audit logs you'd see Falco alerts but
> not know who deployed the pod; without Falco you'd see the pod was created but
> not what commands ran inside.

---

## Falco (runtime security, on VM2)
Falco is an open-source CNCF/Sysdig runtime tool that monitors Linux syscalls
via eBPF. It must run on **VM2** because eBPF monitors LOCAL syscalls only, so it
cannot see activity on remote machines. (The team initially installed it on a
separate VM5 and had to move it.)

**The trigger in this lab:** when the attacker runs `cat /etc/shadow` inside the
privileged `pwned` pod, Falco's eBPF probe intercepts the `openat` syscall and
fires the built-in rule **"Sensitive file opened for reading"** (severity
`Warning`).

> **Detection gap, `/etc/shadow` vs `/host/etc/shadow`:**
> `cat /etc/shadow` (inside the container) traverses the container's filesystem
> namespace and **triggers** Falco. `cat /host/etc/shadow` (via the hostPath
> mount) is a direct passthrough to the host filesystem, bypassing the
> container namespace Falco watches, and does **NOT** trigger an alert.

> Detection relies on Falco's default/built-in ruleset ("Sensitive file opened
> for reading"), so no custom Falco rules were needed for this lab.

---

## Setting up Kibana (Security Onion)
1. Open `https://securityonion`, login with `student@aia.class` / `tartans@1`.
2. Navigate to Kibana > Stack Management > Data Views.
3. Create `k8s-audit-*` data view with `@timestamp`.
4. Create `falco-alerts-*` data view with `@timestamp`.

> Data views are NOT pre-created. You create them during Phase 3.
> Security Onion takes 10-20 minutes to fully start after boot.

---

## Investigating the Audit Logs
Search for `vuln-sa` in the `k8s-audit-*` data view. Key fields / findings:

| Field | Value | Meaning |
|---|---|---|
| `sourceIPs` | `192.168.50.20` | the attacker's IP |
| `user.username` | `system:serviceaccount:vuln-app:vuln-sa` | the stolen identity |
| `verb` | `create` | the attacker created a pod |
| `objectRef.resource` | `pods` | a pod was the target |
| `annotations.authorization.k8s.io/reason` | `RBAC: allowed by ClusterRoleBinding "vuln-sa-admin"` | why it was allowed |

## Investigating the Falco Alerts
Search for `shadow` in the `falco-alerts-*` data view. In the `message` field:

| Field | Value |
|---|---|
| alert | `Warning Sensitive file opened for reading` |
| `file` | `/etc/shadow` |
| `process` | `cat` |
| `command` | `cat /etc/shadow` |
| `parent` | `containerd-shim` (confirms it's from a container) |
| `host.name` | `worker` |
| `container_id` | `787526146d38` |

---

## Detection Quiz (grading_script_2.sh, 10 questions)

**Part A: Kubernetes Audit Logs**
| # | Question | Answer |
|---|---|---|
| Q1 | Attacker's source IP | `192.168.50.20` |
| Q2 | ClusterRoleBinding name | `vuln-sa-admin` |
| Q3 | Service account (namespace:name) | `vuln-app:vuln-sa` |
| Q4 | Resource type created | `pods` |
| Q5 | API verb | `create` |

**Part B: Falco Alerts**
| # | Question | Answer |
|---|---|---|
| Q6 | Sensitive file read | `/etc/shadow` |
| Q7 | Command that triggered alert | `cat /etc/shadow` |
| Q8 | Parent process | `containerd-shim` |
| Q9 | Host name | `worker` |
| Q10 | Falco severity | `Warning` |
