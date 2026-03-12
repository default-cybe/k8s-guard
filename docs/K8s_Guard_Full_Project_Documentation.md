# K8s-Guard: Complete Project Documentation

---

## 1. Project Overview

### What Is K8s-Guard?
K8s-Guard is a 60-minute hands-on cybersecurity lab that teaches students how to attack, detect, and harden a Kubernetes cluster. Students play both attacker and defender in a single session.

### Credits
By Kaivalya Ahir. Built as a small team project.

### Topic
Threat Detection & Monitoring in Kubernetes using the NSA/CISA Kubernetes Hardening Guide, feeding data into Security Onion.

### Platform
A VMware-based lab environment. Up to 5 VMs per workspace. Labs run in isolated networks with no internet access.

### Scope
The original proposal was too ambitious for 60 minutes, so it was trimmed to a single attack chain with detection and hardening. The final lab focuses on one exploit path: LFI → token theft → privilege escalation → detection → hardening.

---

## 2. What Is Kubernetes?

Kubernetes (K8s) is an open-source container orchestration platform originally developed by Google. It automates deploying, scaling, and managing containerized applications across clusters of machines.

### Key Concepts Used In This Lab

**Cluster:** The entire Kubernetes setup. In our lab, VM1 (master) + VM2 (worker) form one cluster.

**Node:** A machine in the cluster. The master node (VM1) runs the API server and makes scheduling decisions. The worker node (VM2) runs the actual application pods.

**Pod:** The smallest deployable unit in Kubernetes. A pod wraps one or more containers. Our webapp runs as a pod. The attack pod (pwned) is also a pod. Both run on VM2.

**Namespace:** A logical partition inside the cluster to organize resources. Our vulnerable app lives in the `vuln-app` namespace.

**Service Account:** A Kubernetes identity assigned to a pod. Every pod gets one automatically. Kubernetes mounts a JWT token at `/var/run/secrets/kubernetes.io/serviceaccount/token` so the pod can authenticate to the API server. In our lab, the webapp pod has the `vuln-sa` service account.

**Token:** The credential file inside the pod. It's a JWT (JSON Web Token) that acts like a password for the service account. If stolen, an attacker can impersonate the pod's identity.

**ClusterRoleBinding:** A permission rule that grants a role across the entire cluster. In our lab, `vuln-sa-admin` is a ClusterRoleBinding that gives `vuln-sa` the `cluster-admin` role, the highest privilege level in Kubernetes.

**RoleBinding:** A permission rule scoped to a single namespace. In hardening, we replace the ClusterRoleBinding with a namespace-scoped RoleBinding.

**NodePort:** A way to expose a pod to the network. Port 30270 on VM2 routes external traffic to the webapp pod inside the cluster.

**Privileged Pod:** A container with all security restrictions disabled. It can access the host's filesystem, processes, and network. This is the `pwned` pod the attacker creates.

### Why Kubernetes Security Matters
- 88% of organizations use Kubernetes in production (CNCF Annual Survey 2023)
- 94% of K8s security incidents involve RBAC misconfigurations (Red Hat State of Kubernetes Security 2024)
- Tesla and Capital One were breached via exposed Kubernetes dashboards and stolen tokens
- Misconfigurations, not zero-days, are the #1 attack vector
- NSA and CISA published a dedicated Kubernetes Hardening Guide in 2022

---

## 3. Lab Architecture

### VM Layout (4 VMs)

| VM | Role | IP | OS | Components | Student Access |
|---|---|---|---|---|---|
| VM1 | K8s Master | 192.168.50.10 | Ubuntu 24 | k3s server, Audit logging, Filebeat | Hardening phase |
| VM2 | K8s Worker | 192.168.50.11 | Ubuntu 24 | Webapp pod, Falco, Filebeat, Flag | Do NOT access |
| VM3 | Attacker | 192.168.50.20 | Kali Linux | kubectl, curl, pwned.yaml | Attack phase |
| VM4 | SIEM | 192.168.50.30 | Security Onion | Elasticsearch, Kibana | Detection phase |

VM5 (originally a standalone Falco VM) was removed. Falco was moved to VM2 because it uses eBPF to monitor local syscalls and cannot see activity on remote machines.

### Credentials
- All Ubuntu/Kali VMs: `student` / `tartans`
- Security Onion web UI: `student@aia.class` / `tartans@1`
- Elasticsearch: `so_elastic` / `<REDACTED-LAB-VALUE>`

### Network
- All VMs on `192.168.50.0/24` (isolated `lan` network in the VMware lab)
- `bridge-net` (internet) used during setup only, removed before student deployment
- No internet access during the lab, so all container images are pre-cached on VM2

### Data Flow
```
VM1 (Audit Logs) ──Filebeat──> VM4 (Security Onion / Elasticsearch)
VM2 (Falco Alerts) ──Filebeat──> VM4 (Security Onion / Elasticsearch)
```

### Attack Path
```
VM3 (Kali) ──curl──> VM2:30270 (LFI) ──token──> VM1:6443 (API) ──kubectl──> VM2 (Privileged Pod)
```

---

## 4. Technologies Used And Why

### k3s (Lightweight Kubernetes)
**What:** A minimal, certified Kubernetes distribution by Rancher Labs. Packages the entire control plane into a single binary.

**Why we used it:** Full Kubernetes (kubeadm) requires 4GB+ RAM per node and multiple components. k3s runs on 2GB RAM. The lab environment has limited resources per VM, so k3s was the only practical choice.

**Alternatives considered:**
- kubeadm: too heavy for our VMs
- minikube: single-node only, can't do master + worker
- kind: runs K8s in Docker containers; networking wouldn't work with our Security Onion setup
- MicroK8s: Ubuntu/snap-specific, less flexible

**How it works:** VM1 runs `k3s server` (master). VM2 runs `k3s agent` (worker). Both configured with `--flannel-iface=ens32` to handle networking without a default gateway.

### Falco (Runtime Security)
**What:** An open-source runtime security tool by Sysdig/CNCF. Monitors Linux system calls (syscalls) at the kernel level using eBPF and fires alerts when behavior matches threat patterns.

**Why we used it:** Kubernetes audit logs only show API-level activity (who created what pod). They cannot see what happens INSIDE a running container. Falco fills this gap. Our project topic requires "a few examples of threat detection monitoring", and Falco provides the runtime layer that audit logs can't.

**How it works:** Falco's eBPF probe hooks into the kernel's syscall interface. When a student runs `cat /etc/shadow` inside the privileged pod, Falco intercepts the `openat` syscall and generates a "Sensitive file opened for reading" alert.

**Critical detail:** `cat /etc/shadow` (inside container) triggers Falco. `cat /host/etc/shadow` (via hostPath mount) does NOT because the hostPath mount bypasses the container's filesystem namespace. Falco's eBPF probe monitors the container namespace, not direct host filesystem access.

**Why on VM2:** Falco monitors LOCAL syscalls only. The attack happens on VM2, so Falco must be on VM2. We initially installed Falco on a separate VM5 (wrong) and had to move it after discovering it couldn't see activity on other machines.

### Security Onion (SIEM)
**What:** An open-source Linux distribution for security monitoring. Bundles Elasticsearch (data storage/search), Kibana (web UI), Logstash, Suricata, Zeek, and other tools.

**Why we used it:** The project topic specifically says "feed this data into an IDS such as Security Onion." It's the industry-standard open-source SIEM and gives students experience with a real enterprise tool.

**How it works:** Security Onion on VM4 receives two data streams via Filebeat: K8s audit logs from VM1 and Falco alerts from VM2. Both are stored in Elasticsearch. Students search and investigate using Kibana.

**Important:** Security Onion takes 10-15 minutes to fully start after boot. It runs ~24 Docker containers managed by a Salt configuration system. The Salt daemon constantly overwrites manual configuration changes, so all firewall rules must be managed through the web UI.

### Filebeat (Log Shipping)
**What:** A lightweight log shipper by Elastic. Reads log files or journal entries and forwards them to Elasticsearch or Logstash.

**Why we used it:** Needed to get logs from VM1 and VM2 into Security Onion's Elasticsearch. Filebeat is lightweight and doesn't require Java.

**Why direct to Elasticsearch:** We tried Logstash (port 5044) first but Security Onion's Salt daemon kept overwriting the Logstash pipeline configuration and the beats input plugin was never properly loaded. After hours of debugging, we switched to sending directly to Elasticsearch on port 9200, which worked immediately.

**Configurations:**
- VM1: Reads `/var/lib/rancher/k3s/server/audit/audit.log`, sends to `k8s-audit-*` index
- VM2: Reads `falco-modern-bpf.service` from systemd journal, sends to `falco-alerts-*` index
- Both use the `so_elastic` user with SSL verification disabled

### Kubernetes Audit Logging
**What:** A built-in Kubernetes feature that records every API request. Logs who did what, from where, to which resource, and whether it was allowed or denied.

**Why we used it:** Primary forensic evidence for investigating Kubernetes attacks. Shows the attacker's exact API calls.

**Configuration:** Via `/etc/rancher/k3s/config.yaml` on VM1 with an audit policy at `/var/lib/rancher/k3s/server/audit/policy.yaml`. Note: `kind: Policy` requires capital P.

**Key fields students find in Kibana:**
- `sourceIPs`: attacker's IP (192.168.50.20)
