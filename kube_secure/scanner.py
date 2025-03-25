import logging
from kubernetes import client, config
from colorama import Fore, Style
import keyring
from kube_secure.logger import log_issue
from tenacity import retry, stop_after_attempt, wait_fixed
import functools

security_issues = []

def load_k8():
    try:
        config.load_kube_config()
        return True
    except:
        try:
            api_server = keyring.get_password("kube-sec", "api_server")
            token = keyring.get_password("kube-sec", "kube_token")
            ssl_verify = keyring.get_password("kube-sec", "SSL_VERIFY")

            configuration = client.Configuration()
            configuration.host = api_server
            configuration.verify_ssl = ssl_verify != "false"
            configuration.api_key = {"authorization": "Bearer " + token}

            client.Configuration.set_default(configuration)
            return True
        except Exception as e:
            logging.error("Error loading Kubernetes config:", e)
            return False

def require_cluster_connection(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not load_k8():
            print("❌ Cluster connection required to run this check.")
            print("💡 Use `kube-sec connect` to authenticate with your Kubernetes cluster.")
            return None
        return func(*args, **kwargs)
    return wrapper

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))     
@require_cluster_connection
def check_cluster_connection():
    try:
        v1 = client.CoreV1Api()
        nodes = v1.list_node().items
        server_version = client.VersionApi().get_code()
      
        pods = v1.list_pod_for_all_namespaces().items

        print("\n🔹 Kubernetes Cluster Information:")
        print(f"   🏷️  API Server Version: {server_version.git_version}")
        print(f"   🔢 Number of Nodes: {len(nodes)}")
       
        return nodes
    except Exception as e:
        print("\n❌ Unable to connect to Kubernetes cluster!")
        print(f"   Error: {str(e)}")
        return None


@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
@require_cluster_connection
def check_privileged_containers_and_hostpath():
    v1 = client.CoreV1Api()
    results = []
    try:
        pods = v1.list_pod_for_all_namespaces().items
        for pod in pods:
            for container in pod.spec.containers:
                is_privileged = container.security_context and container.security_context.privileged
                has_hostpath = False
                if container.volume_mounts:
                    for mount in container.volume_mounts:
                        if "hostPath" in mount.name or mount.mount_path == "/host":
                            has_hostpath = True
                            break
                if is_privileged and has_hostpath:
                    results.append({
                        "Namespace": pod.metadata.namespace,
                        "Pod Name": pod.metadata.name,
                        "Container Name": container.name,
                        "Issue": "Privileged container and HostPath volume mount"
                    })
                elif is_privileged:
                    results.append({
                        "Namespace": pod.metadata.namespace,
                        "Pod Name": pod.metadata.name,
                        "Container Name": container.name,
                        "Issue": "Privileged container"
                    })
                elif has_hostpath:
                    results.append({
                        "Namespace": pod.metadata.namespace,
                        "Pod Name": pod.metadata.name,
                        "Container Name": container.name,
                        "Issue": "HostPath volume mount"
                    })
        return results
    except Exception as e:
        logging.error("Error checking privileged containers and HostPath volumes:", str(e))
        return None

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
@require_cluster_connection
def check_pods_running_as_root():
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

                if (container_run_as_user is None or container_run_as_user == 0) and (pod_run_as_user is None or pod_run_as_user == 0):
                    risky_pods.append({
                        "Namespace": pod.metadata.namespace, 
                        "Pod name": pod.metadata.name})
        return risky_pods
    except Exception as e:
        logging.error("\n❌ Error checking pods running as root:", str(e))
        return None

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
@require_cluster_connection
def check_host_pid_and_network():
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
                log_issue("Warning", message)
        return risky_network_pods
    except Exception as e:
        logging.error("\n❌ Error checking hostPID/hostNetwork:", str(e))
        return None

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
@require_cluster_connection
def check_pods_running_as_non_root():
    v1 = client.CoreV1Api()
    non_root_pods = []
    try:
        pods = v1.list_pod_for_all_namespaces().items
        for pod in pods:
            for container in pod.spec.containers:
                if container.security_context and container.security_context.run_as_non_root is False:
                    non_root_pods.append({
                        "Namespace": pod.metadata.namespace,
                        "Pod name": pod.metadata.name,
                        "Container name": container.name
                    })
        return non_root_pods
    except Exception as e:
        logging.error("Error checking non-root enforcement:", str(e))
        return None

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
@require_cluster_connection
def check_open_ports():
    v1 = client.CoreV1Api()
    services = v1.list_service_for_all_namespaces().items
    open_ports = []
    for svc in services:
        svc_name = svc.metadata.name
        svc_namespace = svc.metadata.namespace
        for port in svc.spec.ports:
            port_number = port.port
            external_ip = "N/A"

            if svc.spec.type in ["LoadBalancer", "NodePort"]:
                if svc.status.load_balancer and svc.status.load_balancer.ingress:
                    external_ip = svc.status.load_balancer.ingress[0].ip if svc.status.load_balancer.ingress[0].ip else "N/A"

                open_ports.append({
                    "namespace": svc_namespace,
                    "service": svc_name,
                    "port": port_number,
                    "type": svc.spec.type,
                    "external_ip": external_ip
                })

    if not open_ports:
        open_ports.append("No insecure open ports detected.")

    return open_ports


@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
@require_cluster_connection
def check_publicly_accessible_services():
    v1 = client.CoreV1Api()
    public_services = []
    try:
        services = v1.list_service_for_all_namespaces().items
        for svc in services:
            if not isinstance(svc, client.V1Service):
                continue
            if svc.spec and svc.spec.type in ["NodePort", "LoadBalancer"]:
                public_services.append({
                    "Namesapce": svc.metadata.namespace, 
                    "Service": svc.metadata.name, 
                    "Type": svc.spec.type})
        return public_services
    except Exception as e:
        logging.error("\n❌ Error checking public services:", str(e))
        return None

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
@require_cluster_connection
def check_network_exposure():
    v1 = client.CoreV1Api()
    public_services = []
    try:
        services = v1.list_service_for_all_namespaces().items
        for svc in services:
            if svc.spec and svc.spec.type in ["NodePort", "LoadBalancer"]:
                svc_namespace = svc.metadata.namespace
                external_ip = svc.status.load_balancer.ingress[0].ip if svc.status.load_balancer and svc.status.load_balancer.ingress else "N/A"
                public_services.append({
                    "Namespace": svc_namespace,
                    "Service": svc.metadata.name,
                    "Type": svc.spec.type,
                    "External IP": external_ip
                })
        return public_services
    except Exception as e:
        logging.error("Error checking network exposure:", str(e))
        return None

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
@require_cluster_connection
def check_weak_firewall_rules():
    networking_v1 = client.NetworkingV1Api()
    try:
        policies = networking_v1.list_network_policy_for_all_namespaces().items
        weak_policies = []
        for policy in policies:
            if not policy.spec.ingress:
                weak_policies.append({
                    "Namespace": policy.metadata.namespace,
                    "Policy": policy.metadata.name
                })
        return weak_policies
    except Exception as e:
        logging.error("Error checking firewall policies:", str(e))
        return None


@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
@require_cluster_connection
def check_rbac_misconfigurations():
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


@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
@require_cluster_connection
def check_rbac_least_privilege():
    rbac_api = client.RbacAuthorizationV1Api()
    risky_roles = []
    try:
        roles = rbac_api.list_cluster_role_binding().items
        for role in roles:
            if role.role_ref.name == "Cluster-admin":
                for subject in role.subjects or []:
                    if subject.kind in ["User", "Group", "ServiceAccount"]:
                        risky_roles.append((subject.kind, subject.name))
        return risky_roles
    except Exception as e:
        logging.error("Error checking RBAC least privilege:", str(e))
        return None


def report_issue(severity, message):
    security_issues.append((severity, message))

def print_security_summary():
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