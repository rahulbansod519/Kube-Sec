from kubernetes import client, config
from colorama import Fore, Style
import json
import os
import csv
from kube_secure.logger import log_issue

def load_k8():
    try:
        # Try loading default kubeconfig (for local access)
        config.load_kube_config()
        return True
    except:
        try:
            # ca_cert_path = "/Users/rahulbansod01/Projects/kube-secure/kube_secure/ca.crt"  # Replace with the CA certificate if needed
            # configuration.verify_ssl = False
            api_server = os.getenv("API_SERVER")
            token = os.getenv("KUBE_TOKEN")

            configuration = client.Configuration()
            configuration.host = api_server
            configuration.verify_ssl = False  # Set to False if not using CA cert
            # configuration.ssl_ca_cert = ca_cert_path
            configuration.api_key = {"authorization": "Bearer " + token}

            client.Configuration.set_default(configuration)
            return True
        except Exception as e:
            print("Error loading Kubernetes config:", e)
            return False
        
def check_cluster_connection():
    """
    Verifies Kubernetes cluster connection and returns basic cluster information.

    """
    if load_k8():
        try:
            # Load kubeconfig

            # Create API client
            v1 = client.CoreV1Api()

            # Get cluster information
            nodes = v1.list_node().items
            server_version = client.VersionApi().get_code()
            pods = v1.list_pod_for_all_namespaces().items


            # Display cluster details
            print("\n🔹 Kubernetes Cluster Information:")
            print(f"   🏷️  API Server Version: {server_version.git_version}")
            print(f"   🔢 Number of Nodes: {len(nodes)}")
            print(f"      Number of Pods: {len(pods)}")

            
            return nodes  # Return the list of nodes

        except Exception as e:
            print("\n❌ Unable to connect to Kubernetes cluster!")
            print(f"   Error: {str(e)}")
            return None
    else:
        print("Unable to connect to cluster")

def check_pods_running_as_root():
    """
    Checks for pods running as root (UID 0) in all namespaces.
    """
    if load_k8():
        v1 = client.CoreV1Api()
        risky_pods = []

        try:
            pods = v1.list_pod_for_all_namespaces().items

            for pod in pods:
                pod_security_context = pod.spec.security_context
                pod_run_as_user = pod_security_context.run_as_user if pod_security_context else None

                for container in pod.spec.containers:
                    container_security_context = container.security_context
                    container_run_as_user = container_security_context.run_as_user if container_security_context else None

                    # If runAsUser is None, it might default to root
                    if (container_run_as_user is None or container_run_as_user == 0) and (pod_run_as_user is None or pod_run_as_user == 0):
                        risky_pods.append((pod.metadata.namespace, pod.metadata.name))

            if risky_pods:
                print("\n⚠️  Found Pods Running as Root:")
                for ns, name in risky_pods:
                    print(f"   - Namespace: {ns}, Pod: {name}")
            else:
                print("\n✅ No Pods are running as root.")

            return {"pods_running_as_root": risky_pods}
        
        except Exception as e:
            print("\n❌ Error checking pods running as root:", str(e))
            return None
        return {"pods_running_as_root": risky_pods}
    else:
        print("Unable to Connect Cluster")
    


def check_rbac_misconfigurations():
    if load_k8():
        rbac_api = client.RbacAuthorizationV1Api()
        risky_user = []
        try:
            roles = rbac_api.list_cluster_role_binding().items
            for role in roles:
                if role.role_ref.name == "Cluster-admin":
                    for subject in role.subjects or []:
                        if subject.kind in ["User", "Group", "ServiceAccount"]:
                            risky_user.append((subject.kind, subject.name))
            if risky_user:
                print("\n Found Users with Cluster-Admin Role")
                for kind, name in risky_user:
                    print(f"    -{kind}: {name}")
            else:
                print("\n No risky RBAC configuration detected")
    

        except Exception as e:
            print("\n Error checking RBAC misconfiguration", str(e))
            return None
        return {"risky_rbac_users": risky_user}
    
    else:
        print("Unable to connect cluster")
    

def check_publicly_accessible_services():
    """
    Identifies services with external exposure (NodePort or LoadBalancer).
    """
    if load_k8():
        v1 = client.CoreV1Api()
        public_services = []

        try:
            services = v1.list_service_for_all_namespaces().items

            for svc in services:
                # Ensure it's a proper Service object
                if not isinstance(svc, client.V1Service):
                    continue  # Skip non-service objects

                # Check if the service is exposed externally
                if svc.spec and svc.spec.type in ["NodePort", "LoadBalancer"]:
                    public_services.append((svc.metadata.namespace, svc.metadata.name, svc.spec.type))

            if public_services:
                print("\n⚠️  Found Publicly Accessible Services:")
                for ns, name, svc_type in public_services:
                    print(f"   - Namespace: {ns}, Service: {name}, Type: {svc_type}")
            else:
                print("\n✅ No publicly exposed services detected.")
            
        

        except Exception as e:
            print("\n❌ Error checking public services:", str(e))

            return None
        return {"public_services": public_services}
    else:
        print("Unable to connect")
    
def check_privileged_containers():
    if load_k8():
        v1 = client.CoreV1Api()
        privileged_containers = []

        try:
            pods = v1.list_pod_for_all_namespaces().items

            for pod in pods:
                for container in pod.spec.containers:
                    if container.security_context and container.security_context.privileged:
                        privileged_containers.append((pod.metadata.namespace, pod.metadata.name, container.name))
                        message = f"Privileged container detected in {pod.metadata.name}/{container.name}"
                        report_issue("Critical", message)  # Logs issue
            
            if privileged_containers:
                print("\n Found Privileged containers: ")
                for ns, pod, container in privileged_containers:
                    print(f"    - Namespace: {ns},  pod: {pod},     Container: {container}")
            else:
                print("\n NO privileged containers found")
        
        except Exception as e:
            print("\n Error Checking privileged containers")

    else:
        print("Error connecting to cluster")

def check_host_pid_and_network():
    if load_k8():

        v1 = client.CoreV1Api()
        risky_pods = []

        try:
            pods = v1.list_pod_for_all_namespaces().items

            for pod in pods:
                if pod.spec.host_pid or pod.spec.host_network:
                    risky_pods.append((pod.metadata.namespace, pod.metadata.name, pod.spec.host_pid, pod.spec.host_network))
                    message = f"Pod {pod.metadata.name} is using hostPID={pod.spec.host_pid}, hostNetwork={pod.spec.host_network}"
                    report_issue("Warning", message)

            if risky_pods:
                print("\n⚠️  Found Pods Using hostPID/hostNetwork:")
                for ns, pod, host_pid, host_net in risky_pods:
                    print(f"   - Namespace: {ns}, Pod: {pod}, hostPID: {host_pid}, hostNetwork: {host_net}")
            else:
                print("\n✅ No pods are using hostPID or hostNetwork.")
        
        except Exception as e:
            print("\n❌ Error checking hostPID/hostNetwork:", str(e))

    else:
        print("Error connectig to cluster")

security_issues = []

def report_issue(severity, message):
    """
    Logs security issues found during the scan.
    """
    security_issues.append((severity, message))

def print_security_summary():
    """
    Displays a final security summary with categorized risks.
    """
    print("\n🔎 Security Scan Summary:")
    
    if not security_issues:
        print(Fore.GREEN + "✅ No security issues found. Your cluster is safe!" + Style.RESET_ALL)
        return

    critical = sum(1 for severity, _ in security_issues if severity == "Critical")
    warning = sum(1 for severity, _ in security_issues if severity == "Warning")

    print(f"{Fore.RED}⚠️  {critical} Critical Issues | {Fore.YELLOW}⚠️  {warning} Warnings{Style.RESET_ALL}\n")

    for severity, message in security_issues:
        color = Fore.RED if severity == "Critical" else Fore.YELLOW
        print(f"   {color}[{severity}] {message}{Style.RESET_ALL}")
        log_issue(severity, message)

def save_json_report():
    """Saves the security issues to a JSON file."""
    report = {
        "summary": {
            "critical": sum(1 for severity, _ in security_issues if severity == "Critical"),
            "warnings": sum(1 for severity, _ in security_issues if severity == "Warning")
        },
        "issues": [{"severity": severity, "message": message} for severity, message in security_issues]
    }

    filename = "security_scan_report.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    
    print(Fore.CYAN + f"\n📂 Report saved: {os.path.abspath(filename)}" + Style.RESET_ALL)


def save_csv_report():
    """Saves the security issues to a CSV file."""
    filename = "security_scan_report.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Severity", "Message"])
        writer.writerows(security_issues)

    print(Fore.CYAN + f"\n📂 CSV Report saved: {os.path.abspath(filename)}" + Style.RESET_ALL)


