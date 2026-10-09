"""Labelled corpus for every detector.

POSITIVES[name] -> list of (text, sensitive_value). The value must be fully
covered by a finding of that detector. NEGATIVES[name] -> texts that must
produce no findings at all.

Every detector in scanner.DETECTORS must appear in both dicts.

Fake credentials are assembled from parts so secret scanners (e.g. GitHub push
protection) don't flag this file.
"""

_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"  # AWS docs example
_GH_BODY = "a1B2c3D4e5F6g7H8i9J0" + "kLmNoPqRsTuVwXyZ01"  # 38 chars
_GH_PAT = "github_" + "pat_" + "11ABCDEFG0" + "123456789012" + "_" + ("Zz9" * 19) + "Qq"
_JWT_HS256 = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
_JWT_NONE = "eyJhbGciOiJub25lIn0" + ".eyJzdWIiOiIxIn0."
_JWT_RS256 = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYyJ9"
    ".eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiZXhwIjoxOTk5OTk5OTk5fQ"
    ".dGhpcy1pcy1hLWZha2Utc2lnbmF0dXJlLXdpdGgtZGFzaGVzX2FuZF91bmRlcnNjb3Jlcw"
)


def _pem(kind: str) -> str:
    label = f"{kind} PRIVATE KEY" if kind else "PRIVATE KEY"
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\nFAKEFAKEFAKEFAKEFAKEFAKE+/==\n"
    return f"-----BEGIN {label}-----\n{body}-----END {label}-----"


# Values that are detectable on their own (no surrounding key name needed).
STANDALONE = {
    "AWS_ACCESS_KEY_ID": [
        "AKIA" + "IOSFODNN7EXAMPLE",
        "ASIA" + "QWERTYUIOP234567",
        "AGPA" + "ZZZZ2222YYYY3333",
        "AROA" + "ABCDEFGHIJKLMNOP",
        "A3TX" + "ABCDEFGHIJKLMNOP",
    ],
    "GITHUB_TOKEN": [
        "ghp_" + _GH_BODY[:36],
        "gho_" + _GH_BODY[:36],
        "ghu_" + _GH_BODY[:36],
        "ghs_" + _GH_BODY[:36],
        "ghr_" + _GH_BODY[:36],
        "ghs_" + _GH_BODY,  # longer than 36 still matched
        _GH_PAT,
    ],
    "JWT": [_JWT_HS256, _JWT_NONE, _JWT_RS256],
    "PRIVATE_KEY": [_pem("RSA"), _pem("EC"), _pem("OPENSSH"), _pem(""), _pem("ENCRYPTED"), _pem("DSA")],
    "DB_CONNECTION_STRING": [
        "postgres://admin:hunter2@db.internal:5432/prod",
        "postgresql://svc:p%40ss@10.0.0.5/analytics?sslmode=require",
        "mysql://root:toor@localhost:3306/app",
        "mariadb://u:p@maria.local/db",
        "mongodb+srv://user:pass@cluster0.example.net/db?retryWrites=true&w=majority",
        "mongodb://user:pass@mongo1:27017,mongo2:27017/db",
        "redis://:s3cret@cache.internal:6379/0",
        "rediss://default:tok@redis.example.com:6380",
        "jdbc:postgresql://pg.example.com:5432/db?user=app&password=secret",
        "jdbc:sqlserver://sql.example.com:1433/db",
        "mssql://sa:Passw0rd@sql.local/master",
        "amqp://guest:guest@rabbit:5672/",
        "Server=tcp:sql.example.com,1433;Database=app;User Id=sa;Password=Sup3r!;",
        "Data Source=db01;Initial Catalog=x;User ID=u;Pwd=p;",
        "Host=pg.local;Port=5432;Username=app;Password=hunter2",
    ],
    "EMAIL_ADDRESS": [
        "jane.doe@example.com",
        "first+tag@sub.example.co.uk",
        "a_b-c@x-y.io",
        "UPPER.CASE@EXAMPLE.ORG",
        "billing%dept@mail.example.com",
    ],
    "US_SSN": ["123-45-6789", "078-05-1120", "899-99-9999", "001-01-0001"],
    "CREDIT_CARD": [
        "4111111111111111",
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        "5500005555555559",
        "378282246310005",
        "3782 822463 10005",
        "6011111111111117",
        "3530111333300000",
        "4222222222222",
    ],
}

# Each standalone value is checked in every one of these surroundings.
CONTEXTS = [
    "{v}",
    "prefix {v} suffix",
    "key={v}",
    "KEY: {v}",
    '"{v}"',
    "'{v}'",
    '{{"field": "{v}", "n": 1}}',
    "<{v}>",
    "[{v}]",
    "\t{v},",
    "line one\n{v}\nline three",
    "Authorization: Bearer {v}",
    "log: value is {v}.",
]

POSITIVES = {name: [(c.format(v=v), v) for v in vals for c in CONTEXTS] for name, vals in STANDALONE.items()}

# Context-dependent detectors list full texts explicitly.
POSITIVES["AWS_SECRET_ACCESS_KEY"] = [
    (f"aws_secret_access_key = {_AWS_SECRET}", _AWS_SECRET),
    (f"AWS_SECRET_ACCESS_KEY={_AWS_SECRET}", _AWS_SECRET),
    (f'export AWS_SECRET_ACCESS_KEY="{_AWS_SECRET}"', _AWS_SECRET),
    (f'{{"SecretAccessKey": "{_AWS_SECRET}"}}', _AWS_SECRET),
    (f"awsSecretAccessKey: '{_AWS_SECRET}'", _AWS_SECRET),
    (f"aws_secret_key:{_AWS_SECRET}", _AWS_SECRET),
    (f"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = {_AWS_SECRET}\n", _AWS_SECRET),
]

NEGATIVES = {
    "AWS_ACCESS_KEY_ID": [
        "AKIA1234",  # too short
        "akiaiosfodnn7example",  # lowercase
        "XAKIAIOSFODNN7EXAMPLEX",  # embedded in a longer word
        "AKIDIOSFODNN7EXAMPLE",  # unknown prefix
    ],
    "AWS_SECRET_ACCESS_KEY": [
        # 40-char values with no AWS key name are left alone (git SHAs etc.)
        "commit 3f786850e387550fdab836ed7e6dc881de23001b",
        f"some_other_field = {_AWS_SECRET}",
        "aws_secret_access_key = tooShort",
    ],
    "GITHUB_TOKEN": [
        "ghp_tooShort123",
        "ghx_" + _GH_BODY[:36],
        "github_pat_short_1234",
        "see https://github.com/org/repo/pulls",
    ],
    "JWT": [
        "eyJustSaying hello",
        "eyJhbGciOiJIUzI1NiJ9 header only",
        "version 1.2.3 released",
    ],
    "PRIVATE_KEY": [
        "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq\n-----END PUBLIC KEY-----",
        "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+g\n-----END CERTIFICATE-----",
        "-----BEGIN RSA PRIVATE KEY----- (truncated, no END marker)",
    ],
    "DB_CONNECTION_STRING": [
        "we migrated from postgres to mysql last year",
        "https://example.com/postgres/docs",
        "Server=web01 is down",
    ],
    "EMAIL_ADDRESS": ["user@localhost", "@handle on twitter", "a@b", "name at example dot com"],
    "US_SSN": ["000-12-3456", "666-12-3456", "900-12-3456", "123-00-4567", "123-45-0000", "123456789"],
    "CREDIT_CARD": [
        "4111111111111112",  # fails Luhn
        "order 123456789012",  # 12 digits, too short
        "1234-5678-9012-3456",  # fails Luhn
        "phone 555-123-4567",
    ],
}
