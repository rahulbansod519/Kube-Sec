import yaml
import logging
import jmespath
from kubernetes import client
from tenacity import retry, stop_after_attempt, wait_fixed

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def load_custom_rules(file_path):
    """Loads a custom rule YAML file."""
    try:
        with open(file_path, 'r') as stream:
            return yaml.safe_load(stream)
    except Exception as e:
        logging.error(f"Failed to load custom rules: {e}")
        return None

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def run_custom_scan(rules):
    """Runs dynamic validation rules against Kubernetes resources."""
    resource_type = rules['spec']['resource']
    rule_list = rules['spec']['rules']
    results = []

    if resource_type.lower() == 'deployment':
        apps_v1 = client.AppsV1Api()
        deployments = apps_v1.list_deployment_for_all_namespaces().items

        for deploy in deployments:
            for rule in rule_list:
                path = rule['field']
                msg = rule.get('message', f"Rule failed: {path}")
                check = evaluate_rule(deploy.to_dict(), path, rule)
                if not check:
                    results.append({
                        'Namespace': deploy.metadata.namespace,
                        'Deployment': deploy.metadata.name,
                        'Rule': path,
                        'Message': msg
                    })
    return results

def evaluate_rule(resource, field_path, rule):
    """Evaluates a single rule on a given Kubernetes resource."""
    try:
        value = jmespath.search(field_path, resource)

        if 'exists' in rule:
            return (value is not None) if rule['exists'] else (value is None)
        if 'equals' in rule:
            return value == rule['equals']
        if 'min' in rule:
            return value is not None and value >= rule['min']
        if 'max' in rule:
            return value is not None and value <= rule['max']

        return True  # fallback to pass if no known condition
    except Exception as e:
        logging.error(f"Error evaluating rule {field_path}: {e}")
        return False
