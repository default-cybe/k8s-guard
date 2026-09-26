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
- **Falco alerts**: runtime syscall activity on the worker node, including
  syscalls made by processes inside containers (eBPF). Shipped by [`filebeat-vm2-falco.yml`](./filebeat-vm2-falco.yml) into the
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
fires the built-in rule **"Read sensitive file untrusted"**, whose alert text
starts with "Sensitive file opened for reading by non-trusted program"
(priority `Warning`).

> **Detection gap, `/etc/shadow` vs `/host/etc/shadow`:**
> `cat /etc/shadow` (inside the container) **triggers** Falco. That reads the
> container image's own `/etc/shadow`. `cat /host/etc/shadow` reads the worker
> node's real `/etc/shadow` through the hostPath mount, and it does **NOT**
> trigger an alert.
>
> This is not because Falco cannot see the host-side read. Falco's eBPF probe
> sees every `open`/`openat` on the node, including opens that go through a
> hostPath bind mount. The gap is in the rule. "Read sensitive file untrusted"
> uses the `sensitive_files` macro, which checks `fd.name in
> (sensitive_file_names)` (rules releases before 3.2.0 also require
> `fd.name startswith /etc`), and that list holds exact paths:
> `[/etc/shadow, /etc/sudoers, /etc/pam.conf, /etc/security/pwquality.conf]`.
> `fd.name` is the path the process opened, as seen from inside the container,
> so the hostPath read arrives as `/host/etc/shadow`. That string is not in the
> list, so the rule does not match and no alert is raised. The macro's other
> branch, `fd.directory in (/etc/sudoers.d, /etc/pam.d)`, is also an exact
> match, so files under `/host/etc/sudoers.d/` and `/host/etc/pam.d/` are
> missed the same way.

> Detection in the graded lab relied only on Falco's default ruleset ("Read
> sensitive file untrusted"). No custom Falco rules were loaded during the lab.

### Follow-up rule for the hostPath gap (not part of the graded lab)

The rule below closes the gap by matching the sensitive file names as path
suffixes, so `/host/etc/shadow` (or a host file mounted under any other mount
point) matches. It is also in
[`falco-rule-hostpath-sensitive-read.yaml`](./falco-rule-hostpath-sensitive-read.yaml).

**Status:** written after the lab. It was not loaded into Falco during the lab
run and has not yet been tested against the lab cluster, so there is no alert
output to show for it. The fields and operators (`fd.name`, `endswith`, `in`,
the `open_read` and `container` macros, `sensitive_file_names`) are taken from
the Falco documentation and the upstream `falco_rules.yaml`.

```yaml
- macro: sensitive_file_via_other_path
  condition: >
    (fd.name endswith "/etc/shadow" or
     fd.name endswith "/etc/sudoers" or
     fd.name endswith "/etc/pam.conf" or
     fd.name endswith "/etc/security/pwquality.conf")
    and not fd.name in (sensitive_file_names)

- rule: Read sensitive file through non-standard path in container
  desc: >
    A process in a container opened a sensitive file through a path other than
    its standard one, for example /host/etc/shadow through a hostPath volume
    mounted at /host. The default rule "Read sensitive file untrusted" checks an
    exact list of paths and does not match this.
  condition: >
    open_read
    and container
    and sensitive_file_via_other_path
  output: >
    Sensitive file opened for reading through a non-standard path in a container
    | file=%fd.name process=%proc.name command=%proc.cmdline parent=%proc.pname
    user=%user.name container_id=%container.id container_name=%container.name
    image=%container.image.repository k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name
  priority: WARNING
  tags: [container, filesystem, mitre_credential_access, T1003.008]
```

To test it on VM2: load it after the default rules (it uses the
`sensitive_file_names` list and the `open_read` and `container` macros from
`falco_rules.yaml`). The default `falco.yaml` loads
`/etc/falco/falco_rules.yaml`, then `/etc/falco/falco_rules.local.yaml`, then
`/etc/falco/rules.d`, so copying the file into `/etc/falco/rules.d/` is enough.
Restart `falco-modern-bpf.service`, then
run `kubectl ... exec pwned -n vuln-app -- cat /host/etc/shadow` from Kali
(`kubectl ...` is the `--server`/`--token` shorthand from ATTACK.md). The
expected result is one `Warning` alert with `file=/host/etc/shadow`.

The `and not fd.name in (sensitive_file_names)` line keeps the rule from
duplicating the default rule's alert for `/etc/shadow` itself. The rule covers
only the four file names in `sensitive_file_names`; it does not cover files
under `/etc/sudoers.d` or `/etc/pam.d` read through another path. The rule does
not apply the default rule's allowlist of trusted programs, so node agents
that legitimately read host files through a hostPath mount may need an
exception.

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
