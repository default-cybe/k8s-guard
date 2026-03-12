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
   and Falco runtime alerts (in-container syscalls).
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

