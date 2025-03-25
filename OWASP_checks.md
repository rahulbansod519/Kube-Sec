## ✅ Features Already Implemented (OWASP Alignment)

| Category               | OWASP Concern                 | Your Feature                                                               | Status |
|------------------------|-------------------------------|-----------------------------------------------------------------------------|--------|
| **Authentication & Secrets** | Secure credential storage       | API tokens saved using `keyring`, not plaintext                            | ✅     |
| **Least Privilege**         | Detect RBAC misconfigurations   | `check_rbac_misconfigurations()` warns on `cluster-admin` bindings         | ✅     |
| **Running as Root**         | Container hardening             | `check_pods_running_as_root()` flags UID 0                                 | ✅     |
| **Privileged Containers**   | Over-privileged workloads       | `check_privileged_containers()` with severity=Critical                     | ✅     |
| **Host Access**             | Host PID / Network leakage      | `check_host_pid_and_network()` warns on `hostPID` / `hostNetwork`         | ✅     |
| **Network Exposure**        | Public attack surface           | `check_publicly_accessible_services()` and `check_open_ports()`           | ✅     |
| **Firewall Rules**          | Network segmentation            | `check_weak_firewall_rules()` flags missing ingress rules                  | ✅     |
| **Secure Logs**             | Log auditing                    | Logs are timestamped and separated from terminal output                    | ✅     |
| **Output Clarity**          | Report visibility               | Output includes summaries, tabular view, JSON/YAML reports                 | ✅     |
| **Session Handling**        | Logout/cleanup                  | `kube-sec disconnect` clears API tokens                                    | ✅     |

---

## 🟡 Recommended Features to Add (OWASP Inspired)

| Category               | Suggestion                                                             | Priority |
|------------------------|------------------------------------------------------------------------|----------|
| **Security Monitoring**     | Support sending scan reports via webhook, Slack, or email             | 🔼 High  |
| **Audit Trail**             | Include scanner username, cluster name in metadata                    | 🔼 High  |
| **Kubernetes CIS Benchmarks** | Integrate with CIS-recommended checks (API server flags, etc.)         | 🔼 High  |
| **Secrets in Env/Volumes**  | Detect hardcoded secrets in pod specs (e.g., env vars or mounted secrets) | 🔼 High  |
| **Pod Security Standards**  | Check for compliance with `restricted` PSP or PSS                     | 🔼 Medium|
| **Deprecated APIs**         | Warn about deprecated or removed API versions (e.g., `extensions/v1beta1`) | 🔼 Medium|
| **Resource Limits**         | Check if containers lack `cpu` / `memory` limits                       | 🟡 Medium|
| **Auto-Fix Suggestions**    | Output YAML patch suggestions or kubectl commands                     | 🟡 Medium|
| **Signed Images**           | Warn if images don’t use digests or are not signed                    | 🟡 Low   |
| **Third-Party Exposure**    | Scan for public images from unknown registries                        | 🟡 Low   |
