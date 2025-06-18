import boto3
import base64
import json
import os
from pathlib import Path

# Load environment/config values
SECRET_NAME = os.getenv("SECRET_NAME", "dremio-cert-secret")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "manifests/secret-tls.yaml")
NAMESPACE = os.getenv("NAMESPACE", "default")

# Fetch secret from AWS Secrets Manager
def get_secret():
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=AWS_REGION)
    
    try:
        get_secret_value_response = client.get_secret_value(SecretId=SECRET_NAME)
        secret_data = get_secret_value_response['SecretString']
        return json.loads(secret_data)
    except Exception as e:
        print(f"Error fetching secret: {e}")
        return None

# Generate Kubernetes TLS secret manifest
def write_k8s_secret(cert: str, key: str):
    Path("manifests").mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        f.write(f"""
apiVersion: v1
kind: Secret
metadata:
  name: dremio-tls
  namespace: {NAMESPACE}
type: kubernetes.io/tls
data:
  tls.crt: {cert}
  tls.key: {key}
""")
        print(f"✅ Secret manifest written to {OUTPUT_FILE}")

if __name__ == "__main__":
    secret = get_secret()
    if secret and 'tls.crt' in secret and 'tls.key' in secret:
        # Base64 encode cert and key
        crt_b64 = base64.b64encode(secret['tls.crt'].encode()).decode()
        key_b64 = base64.b64encode(secret['tls.key'].encode()).decode()
        write_k8s_secret(crt_b64, key_b64)
    else:
        print("❌ Missing tls.crt or tls.key in secret")

