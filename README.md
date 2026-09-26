# K8s-Guard

> **Attack. Detect. Harden.** A 60-minute hands-on Kubernetes security lab where
> you play both attacker and defender against a vulnerable k3s cluster. You chain
> an LFI into a full cluster takeover, catch it in Falco + Security Onion, then
> harden the cluster per the NSA/CISA Kubernetes Hardening Guide.

A self-contained lab on *Threat Detection & Monitoring in Kubernetes using the
NSA/CISA Kubernetes Hardening Guide, feeding data into Security Onion.*

---

## What this lab teaches

You walk one complete exploit path end-to-end, wearing a few different hats:

1. **Attack.** Turn a web app's Local File Inclusion bug into theft of a
   Kubernetes service-account token, use that token to reach the API server,
   find an over-permissive `cluster-admin` binding, deploy a privileged pod,
   and escape to the host to capture a flag.
2. **Detect.** Now switch to defender. Investigate the attack in Security Onion
   (Kibana) using two telemetry streams: Kubernetes audit logs (API activity)
   and Falco runtime alerts (syscalls on the worker node, including inside
   containers).
3. **Harden.** Remediate with least-privilege RBAC and Pod Security Standards,
   mapped to the NSA/CISA Kubernetes Hardening Guide v1.2.

The core lesson: misconfigurations, not zero-days, are the #1 K8s attack
vector, and the right controls limit the blast radius even when the app stays
vulnerable.

---

## The attack chain

```
                        ┌──────────────────────────────────────────────────┐
                        │              THREE CHAINED MISCONFIGS             │
                        │  (1) LFI   (2) RBAC=cluster-admin   (3) no PSS    │
                        └──────────────────────────────────────────────────┘

  VM3 Kali            VM2 Worker (webapp)         VM1 Master (API)      VM2 Worker (host)
 192.168.50.20        192.168.50.11:30270        192.168.50.10:6443
     │                       │                          │                    │
     │  curl /read?file=     │                          │                    │
     │  ...serviceaccount/   │                          │                    │
     │─────token────────────▶│                          │                    │
     │◀──── JWT token ───────│                          │                    │
     │                       │   kubectl --token=$TOKEN │                    │
     │──────────────────────────────────────────────── ▶│  get nodes / RBAC  │
     │                       │   found: ClusterRoleBinding vuln-sa-admin      │
     │                       │          = cluster-admin │                    │
     │   kubectl apply -f pwned.yaml (privileged pod)   │                    │
     │──────────────────────────────────────────────── ▶│─── schedule ──────▶│
     │   kubectl exec pwned -- cat /host/root/flag/proof.txt                  │
     │──────────────────────────────────────────────────────────────────────▶│
     │◀────────────  FLAG{k8s_privilege_escalation_successful}  ──────────────│

   LFI opens the door, RBAC hands over the keys, and no PSS lets the attacker walk out.
```

<details>
<summary>Same diagram as Mermaid</summary>

```mermaid
flowchart LR
    A[VM3 Kali\n192.168.50.20] -->|curl LFI /read?file=| B[VM2 webapp\n:30270]
    B -->|steals SA JWT token| A
    A -->|kubectl --token=$TOKEN| C[VM1 API server\n:6443]
    C -->|RBAC: vuln-sa-admin = cluster-admin| A
    A -->|apply pwned.yaml privileged pod| C
    C -->|schedules pod nodeName=worker| D[VM2 host]
    A -->|exec cat /host/root/flag/proof.txt| D
    D -->|FLAG| A
```
</details>

---

## Repo layout

```
k8s-guard/
├── README.md                     ← you are here
├── docs/                         ← original source material (unmodified)
│   └── K8s_Guard_Full_Project_Documentation.md
├── manifests/                    ← vulnerable-cluster Kubernetes YAML
│   ├── 00-namespace.yaml                     vuln-app namespace (no PSS = Vuln 3)
│   ├── 01-serviceaccount-vuln-sa.yaml        vuln-sa service account (token target)
│   ├── 02-clusterrolebinding-vuln-sa-admin.yaml  vuln-sa → cluster-admin (Vuln 2)
│   ├── 03-webapp-pod.yaml                     Internal Document Portal w/ LFI (Vuln 1)
│   └── 04-webapp-svc.yaml                     NodePort webapp-svc on 30270
├── attack/                       ← attacker's perspective
│   ├── ATTACK.md                             numbered attack-chain walkthrough
│   └── pwned.yaml                            privileged attack pod
├── detection/                    ← defender's perspective (Security Onion)
│   ├── DETECTION.md                          audit + Falco investigation guide
│   ├── falco-rule-hostpath-sensitive-read.yaml  follow-up rule for the hostPath gap (not run in the lab)
│   ├── k3s-audit-config.yaml                 K8s audit logging config (VM1)
│   ├── filebeat-vm1-audit.yml                ships audit logs → Elasticsearch (redacted)
│   └── filebeat-vm2-falco.yml                ships Falco alerts → Elasticsearch (redacted)
└── hardening/                    ← remediation (NSA/CISA guide)
    ├── HARDENING.md                          3 fixes mapped to NSA/CISA sections
    ├── hardened-role.yaml                    least-privilege Role (get/list pods)
    ├── hardened-rolebinding.yaml             binds Role to vuln-sa (namespace-scoped)
    └── namespace-hardened.yaml               vuln-app + restricted PSS label
```

## Quickstart

- **Attackers:** start at [`attack/ATTACK.md`](./attack/ATTACK.md). Every
  command, in order, from Kali.
- **Defenders:** go to [`detection/DETECTION.md`](./detection/DETECTION.md) for
  how to find the attack in Security Onion / Kibana.
- **Hardeners:** go to [`hardening/HARDENING.md`](./hardening/HARDENING.md) for
  the three fixes and their NSA/CISA mappings.
- **Full context:** [`docs/K8s_Guard_Full_Project_Documentation.md`](./docs/K8s_Guard_Full_Project_Documentation.md).
  It is kept unmodified. Its explanation of the Falco hostPath gap, its
  NSA/CISA section numbers and its "even with cluster-admin" claim are
  corrected in `detection/DETECTION.md` and `hardening/HARDENING.md`; where
  they disagree, those files are current.

---

## MITRE ATT&CK mapping

MITRE ATT&CK (Enterprise) technique IDs mapped to the lab's attack steps. All
of them except T1003.008 (a Linux-platform technique) are also in the
ATT&CK Containers matrix.

| Phase | Documented action | Tactic | Technique |
|---|---|---|---|
| Recon | LFI reads arbitrary files via `/read?file=` | Initial Access | T1190 Exploit Public-Facing Application |
| Recon | Steal the SA token from `/var/run/secrets/.../token` | Credential Access | T1528 Steal Application Access Token |
| Recon | `nmap -p 6443` for the API server | Discovery | T1046 Network Service Discovery |
| Recon | Enumerate ClusterRoleBindings via kubectl | Discovery | T1613 Container and Resource Discovery |
| Escalation | Deploy privileged pod with stolen cluster-admin token | Execution | T1610 Deploy Container |
| Escalation | hostPath `/` mount + `hostPID`/`hostNetwork`, read the host filesystem | Privilege Escalation | T1611 Escape to Host |
| Escalation | `cat /etc/shadow` inside the container | Credential Access | T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow |

Reading the token through the file-read bug also fits T1552.001 Unsecured
Credentials: Credentials In Files. T1528 is used here because its ATT&CK
description names stolen Kubernetes service-account tokens specifically.

---

## Lab environment

Originally built and run in **a VMware lab environment** (isolated, no
internet) using **k3s** (lightweight Kubernetes). Four VMs on an isolated
`192.168.50.0/24` network:

| VM | Role | IP | OS | Student phase |
|---|---|---|---|---|
| VM1 | k3s master | 192.168.50.10 | Ubuntu 24 | Hardening |
| VM2 | k3s worker (webapp, Falco, flag) | 192.168.50.11 | Ubuntu 24 | n/a (do not access) |
| VM3 | Attacker | 192.168.50.20 | Kali Linux | Attack |
| VM4 | SIEM (Security Onion) | 192.168.50.30 | Security Onion | Detection |

Container images (`nginx`, `python:3.9-slim`) are pre-cached on VM2 for
airgapped operation; k3s uses `--flannel-iface=ens32` to network without a
default gateway.

---

## Credits

By Kaivalya Ahir. Built as a small team project.

---

## References

- NSA & CISA. *Kubernetes Hardening Guide v1.2* (August 2022).
- CNCF *Annual Survey 2023*; Red Hat *State of Kubernetes Security 2024*.
- Falco, Kubernetes RBAC / Pod Security Standards, Security Onion, and k3s docs.

_See `docs/K8s_Guard_Full_Project_Documentation.md` Section 14 for full citations._
