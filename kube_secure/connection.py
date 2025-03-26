import logging
import keyring
from kubernetes import client, config
from kubernetes.client.rest import ApiException


def test_cluster_connection(api_server=None, token=None, ssl_verify=False, kubeconfig=False):
    """Test connection to the Kubernetes cluster by performing an API call."""
    try:
        # Set up configuration
        configuration = client.Configuration()
        if api_server:
            configuration.host = api_server
        configuration.verify_ssl = ssl_verify
        if token:
            configuration.api_key = {"authorization": "Bearer " + token}
        
        client.Configuration.set_default(configuration)

        # Attempt a basic API call to verify connection
        v1 = client.CoreV1Api()
        v1.list_namespace(limit=1)  # Check namespaces to test connection

        logging.info("✅ Cluster connection successful.")
        save_credentials(api_server,token,ssl_verify)
        return True
    except ApiException as e:
        logging.error(f"❌ Cluster connection failed: {e}")
        return False
    except Exception as e:
        logging.error(f"❌ Unexpected error while connecting: {e}")
        return False



def save_credentials(api_server, token, ssl_verify=False):
    """Save API server, token, and SSL settings to keyring."""
    keyring.set_password("kube-sec", "api_server", api_server)
    keyring.set_password("kube-sec", "kube_token", token)
    keyring.set_password("kube-sec", "SSL_VERIFY", str(ssl_verify))
    logging.info("✅ Credentials saved securely using system keyring.")


def load_credentials():
    """Load credentials from keyring."""
    api_server = keyring.get_password("kube-sec", "api_server")
    token = keyring.get_password("kube-sec", "kube_token")
    ssl_verify = keyring.get_password("kube-sec", "SSL_VERIFY")
    return api_server, token, ssl_verify


def connect_to_cluster(api_server=None, token=None, token_path=None, ssl_verify=False, kubeconfig=False):
    """Main entry point for connecting to the cluster using kubeconfig or token-based authentication."""

    if kubeconfig:
        try:
            # If --kubeconfig flag is set, load kubeconfig
            config.load_kube_config()  # This will load ~/.kube/config by default
            logging.info("✅ Using kubeconfig for authentication.")
            return True
        except Exception as e:
            logging.error(f"❌ Error loading kubeconfig: {e}")
            return False

    if not api_server or not token:
        logging.error("❌ No valid credentials provided. Please provide API server and token or use --kubeconfig.")
        return False

    # If token is provided, attempt to connect using token credentials
    return test_cluster_connection(api_server, token, ssl_verify, kubeconfig)
