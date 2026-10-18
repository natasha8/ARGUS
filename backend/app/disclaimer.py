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
        "id": "data_exposure",
        "title": "Excessive data exposure",
        "owasp": "API3:2023",
        "summary": "Checks whether authenticated reads return sensitive properties such as password hashes or reset tokens.",
    },
    {
        "id": "resource_limits",
        "title": "Resource consumption",
        "owasp": "API4:2023",
        "summary": "Checks whether a list returns as many rows as requested, and whether rate-limit headers are missing.",
    },
    {
        "id": "bfla",
        "title": "BFLA",
        "owasp": "API5:2023",
        "summary": "Checks whether administrative functions accept a low-privilege role.",
    },
    {
        "id": "business_flow",
        "title": "Sensitive business flow (opt-in)",
        "owasp": "API6:2023",
        "summary": "Opt-in: repeats one checkout-like POST with the same idempotency key. Off by default because it can create objects.",
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
    {
        "id": "misconfig",
        "title": "Security misconfiguration",
        "owasp": "API8:2023",
        "summary": "Checks CORS origin reflection, missing security headers, and verbose error disclosure.",
    },
    {
        "id": "inventory",
        "title": "API inventory",
        "owasp": "API9:2023",
        "summary": "Requests the previous API version declared in the specification and reports it when that version still responds.",
    },
    {
        "id": "unsafe_consumption",
        "title": "Unsafe API consumption",
        "owasp": "API10:2023",
        "summary": "Checks whether a provider parameter makes the server copy an upstream response into its own result.",
    },
    {
        "id": "mass_assignment",
        "title": "Mass assignment (opt-in)",
        "owasp": "API3:2023",
        "summary": "Opt-in and state-changing: flips a privileged property via PATCH/PUT on an object it can read back, then restores it. Off by default.",
    },
]

ALLOWED_CHECKS = {item["id"] for item in CHECK_CATALOG}
