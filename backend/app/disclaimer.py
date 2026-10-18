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
]

ALLOWED_CHECKS = {item["id"] for item in CHECK_CATALOG}
