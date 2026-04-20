"""RBAC — M6. 3 role: user / admin / mailing_list_manager."""

PERMISSIONS = {
    "user":                  {"smtp.send", "pop3.fetch"},
    "mailing_list_manager":  {"smtp.send", "pop3.fetch", "list.manage"},
    "admin":                 {"smtp.send", "pop3.fetch", "list.manage",
                              "audit.view", "user.manage", "crl.view"},
}


def allowed(role: str, action: str) -> bool:
    return action in PERMISSIONS.get(role, set())
