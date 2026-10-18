DISCLAIMER = (
    "Use Argus only against APIs you are explicitly authorized to test. "
    "Scanning systems without permission can be illegal."
)

CHECK_CATALOG = [
    {
        "id": "bola",
        "title": "BOLA / IDOR",
        "owasp": "API1:2023",
        "summary": "Checks whether an authenticated user can read another user's object.",
    },
    {
        "id": "auth_jwt",
        "title": "JWT authentication",
        "owasp": "API2:2023",
        "summary": "Checks weak secrets, unsigned tokens, ignored expiry, and forged role claims.",
    },
    {
        "id": "bfla",
        "title": "BFLA",
        "owasp": "API5:2023",
        "summary": "Checks whether administrative functions accept a low-privilege role.",
    },
    {
        "id": "ssrf",
        "title": "SSRF",
        "owasp": "API7:2023",
        "summary": "Checks whether a URL parameter makes the server call a lab callback.",
    },
    {
        "id": "injection",
        "title": "Injection",
        "owasp": "A03:2021",
        "summary": "Looks for SQL injection, NoSQL operators, and command-like parameters, using non-destructive probes.",
    },
]

ALLOWED_CHECKS = {item["id"] for item in CHECK_CATALOG}
