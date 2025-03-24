import logging
from kubernetes import client, config
from colorama import Fore, Style
import os
from kube_secure.logger import log_issue

def load_k8():
    try:
        # Try loading default kubeconfig (for local access)
        config.load_kube_config()
        return True
    except:
        try:
            
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
            logging.error("Error loading Kubernetes config:", e)
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
                        risky_pods.append({
                            "Namespace": pod.metadata.namespace, 
                            "Pod name": pod.metadata.name})

           
            return risky_pods
        
        except Exception as e:
            logging.error("\n❌ Error checking pods running as root:", str(e))
            
    
    else:
        logging.error("Unable to Connect Cluster")
    


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
      
            return risky_user

        except Exception as e:
            logging.error("\n Error checking RBAC misconfiguration", str(e))
            
        
    
    else:
        logging.error("Unable to connect cluster")
    

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
                    public_services.append({
                        "Namesapce": svc.metadata.namespace, 
                        "Service": svc.metadata.name, 
                        "Type": svc.spec.type})

        
            return public_services

        except Exception as e:
            logging.error("\n❌ Error checking public services:", str(e))
            
        
    else:
        logging.error("Unable to connect")
    
def check_privileged_containers():
    if load_k8():
        v1 = client.CoreV1Api()
        privileged_containers = []

        try:
            pods = v1.list_pod_for_all_namespaces().items

            for pod in pods:
                for container in pod.spec.containers:
                    if container.security_context and container.security_context.privileged:
                        privileged_containers.append({
                            "Namesapce": pod.metadata.namespace, 
                            "Pod Name": pod.metadata.name, 
                            "Container Name":  container.name})
                        
                        message = f"Privileged container detected in {pod.metadata.name}/{container.name}"
                        report_issue("Critical", message)  # Logs issue
        
            return privileged_containers
        
        except Exception as e:
            logging.error("\n Error Checking privileged containers")

    else:
        print("Error connecting to cluster")

def check_host_pid_and_network():
    if load_k8():

        v1 = client.CoreV1Api()
        risky_network_pods = []

        try:
            pods = v1.list_pod_for_all_namespaces().items

            for pod in pods:
                if pod.spec.host_pid or pod.spec.host_network:
                    risky_network_pods.append({
                        "Namespace": pod.metadata.namespace, 
                        "Pod Name": pod.metadata.name, 
                        "Host PID": pod.spec.host_pid, 
                        "Host Network": pod.spec.host_network})
                    
                    message = f"Pod {pod.metadata.name} is using hostPID={pod.spec.host_pid}, hostNetwork={pod.spec.host_network}"
                    report_issue("Warning", message)

            return risky_network_pods
        
        except Exception as e:
            logging.error("\n❌ Error checking hostPID/hostNetwork:", str(e))

    else:
        logging.error("Error connectig to cluster")

def check_open_ports():
    """Detects services with open ports and potential exposure."""
    if load_k8():

        v1 = client.CoreV1Api()
        services = v1.list_service_for_all_namespaces().items
        open_ports = []

        for svc in services:
            svc_name = svc.metadata.name
            namespace = svc.metadata.namespace
            for port in svc.spec.ports:
                port_number = port.port
                external_ip = "N/A"

                if svc.spec.type in ["LoadBalancer", "NodePort"]:
                    if svc.status.load_balancer and svc.status.load_balancer.ingress:
                        external_ip = svc.status.load_balancer.ingress[0].ip if svc.status.load_balancer.ingress[0].ip else "N/A"

                    open_ports.append({
                        "namespace": namespace,
                        "service": svc_name,
                        "port": port_number,
                        "type": svc.spec.type,
                        "external_ip": external_ip
                    })

        if open_ports:
            logging.warning("Detected services with open ports:\n")
        else:
            logging.info("No insecure open ports detected.")
            open_ports.append("No insecure open ports detected.")


        return open_ports
    else:
        logging.error("Cluster Connection lost")

def check_weak_firewall_rules():
    """Detects services that are accessible from the public internet."""
    if load_k8():
    
        networking_v1 = client.NetworkingV1Api()
        network_policies = networking_v1.list_network_policy_for_all_namespaces().items
        weak_policies = []
        
        for policy in network_policies:
            if not policy.spec.ingress:
                weak_policies.append({"Policy": policy.metadata.name})
        
        if weak_policies:
            logging.warning("Found network policies allowing unrestricted access")
        else:
            logging.info("All network policies are properly configured.")
            weak_policies.append("All network policies are properly configured.")
        
        return weak_policies
    else:
        logging.error("luster Connection lost")

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



