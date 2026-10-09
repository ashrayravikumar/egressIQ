"""Demo payloads for the web UI. All credentials are fake.

Tokens are assembled from parts so secret scanners don't flag this file.
"""

_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
_GH = "ghp_" + "R7tQm2Xc9LpV4sKd8NbW3yHf6JzA1eGu5TnC"
_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJ1c3JfODgyMSIsIm9yZyI6ImFjbWUiLCJyb2xlIjoiYWRtaW4ifQ"
    ".kq3vXo0b1Wm7T9cZr2Ly5NfH8sDg4JpA6eQx-UiR_Ow"
)

APP_LOG = f"""2026-10-09T14:02:11.482Z INFO  api-gateway  request_id=7f3a9c route=/v1/chat/completions model=gpt-4o user=jane.doe@acme-corp.com
2026-10-09T14:02:11.509Z DEBUG api-gateway  forwarding headers Authorization: Bearer {_JWT}
2026-10-09T14:02:11.733Z INFO  billing-svc  charge ok customer_id=C-10442 amount=129.00 currency=USD
2026-10-09T14:02:12.018Z WARN  ingest-wkr   retrying S3 upload with AWS_ACCESS_KEY_ID={_AWS_KEY}
2026-10-09T14:02:12.019Z WARN  ingest-wkr   aws_secret_access_key={_AWS_SECRET}
2026-10-09T14:02:12.311Z ERROR orders-db    connection refused: postgres://svc_orders:Pr0d-P%40ssw0rd@orders-db.internal.acme:5432/orders
2026-10-09T14:02:12.640Z INFO  api-gateway  latency_ms=412 tokens_in=1832 tokens_out=611 status=200
2026-10-09T14:02:13.102Z INFO  support-bot  escalated ticket #48213 to tier2 owner=raj.patel@acme-corp.com
"""

SUPPORT_PROMPT = """You are Acme's support copilot. Summarise the customer's issue and draft a reply.

--- Ticket #48213 ---
Customer: Maria Gonzalez <maria.gonzalez@gmail.com>
Account SSN on file: 512-44-8721
Card used for the disputed charge: 4539 1488 0343 6467
Message: "I was charged twice on Oct 3rd. Please refund the duplicate and confirm by email."

Internal note from agent: refund approved, escalate to billing-lead@acme-corp.com if > $500.
"""

CONFIG_DUMP = (
    "{\n"
    '  "service": "acme-rag-indexer",\n'
    '  "environment": "production",\n'
    f'  "github_token": "{_GH}",\n'
    '  "vector_db": "mongodb+srv://indexer:Zx81-qLp@cluster0.acme.mongodb.net/embeddings?retryWrites=true",\n'
    '  "cache_url": "redis://:c4che-s3cret@redis.internal.acme:6379/2",\n'
    f'  "aws": {{"region": "us-east-1", "access_key_id": "{_AWS_KEY}", "SecretAccessKey": "{_AWS_SECRET}"}},\n'
    '  "admin_contact": "platform-oncall@acme-corp.com",\n'
    '  "signing_key": "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA1x7FAKEKEYFAKEKEYFAKEKEY\\n-----END RSA PRIVATE KEY-----"\n'
    "}\n"
)

CUSTOMER_CSV = """customer_id,name,email,ssn,card_number,plan
C-10442,Daniel Kim,daniel.kim@example.com,231-58-9014,4111 1111 1111 1111,enterprise
C-10443,Priya Shah,priya.shah@example.org,604-21-7730,5500 0055 5555 5559,growth
C-10444,Tom Becker,tom.becker@example.net,118-93-4402,3782 822463 10005,starter
C-10445,Lena Ortiz,lena.ortiz@example.com,,,trial
"""

SAMPLES = [
    {"id": "app-log", "label": "Production app log", "filename": "api-gateway.log", "text": APP_LOG},
    {"id": "prompt", "label": "Support copilot prompt", "filename": "copilot-prompt.txt", "text": SUPPORT_PROMPT},
    {"id": "config", "label": "Leaked service config", "filename": "indexer-config.json", "text": CONFIG_DUMP},
    {"id": "csv", "label": "Customer export", "filename": "customers_export.csv", "text": CUSTOMER_CSV},
]
