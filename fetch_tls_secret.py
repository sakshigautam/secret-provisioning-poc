import boto3
import base64
import json
import os
import yaml

from pathlib import Path

# Load environment/config values
SECRET_NAME = os.getenv("SECRET_NAME", "dremio-cert-secret")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
VALUES_FILE = os.getenv("VALUES_FILE", "charts/tls-secret/values.yaml")

# Fetch secret from AWS Secrets Manager
def get_secret():
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=AWS_REGION)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=SECRET_NAME)
        secret_data = get_secret_value_response['SecretString']
        return json.loads(secret_data)
    except Exception as e:
        print(f"❌ Error fetching secret: {e}")
        return None

# Update Helm values.yaml with base64-encoded cert + key
def update_helm_values(cert: str, key: str):
    if not Path(VALUES_FILE).exists():
        print(f"❌ {VALUES_FILE} not found!")
        return

    with open(VALUES_FILE, "r") as f:
        values = yaml.safe_load(f)

    # Ensure correct structure exists
    if "tlsSecret" not in values:
        values["tlsSecret"] = {}

    values["tlsSecret"]["name"] = "dremio-tls"
    values["tlsSecret"]["namespace"] = "default"
    values["tlsSecret"]["data"] = {
        "tls.crt": cert,
        "tls.key": key
    }

    with open(VALUES_FILE, "w") as f:
        yaml.dump(values, f, default_flow_style=False)

    print(f"✅ Updated {VALUES_FILE} with latest cert and key")

# Main
if __name__ == "__main__":
    secret = get_secret()
    if secret and 'tls.crt' in secret and 'tls.key' in secret:
        crt_b64 = base64.b64encode(secret['tls.crt'].encode()).decode()
        key_b64 = base64.b64encode(secret['tls.key'].encode()).decode()
        update_helm_values(crt_b64, key_b64)
    else:
        print("❌ Missing tls.crt or tls.key in secret")