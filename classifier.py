import re

ALLOW = "allow"
BLOCK = "block"
REVIEW = "review"
NONE = "none"
PRIMARY = "primary"
RESTRICTED = "restricted"
NORMAL = "normal"
WATCH = "watch"
INTERVENE = "intervene"

READ_OPS = {"read", "inspect", "list", "git_status", "plan"}

CONSEQUENTIAL_OPS = {
    "delete", "write", "create", "update", "send", "upload",
    "transfer", "push", "deploy", "mutate", "docker", "dns",
}

HARMFUL_PATTERNS = [
    r"\b(exfiltrate|steal)\b.{0,50}\b(credential|password|secret|token|api[_ -]?key|private data)\b",
    r"\b(credential|password|secret|token|api[_ -]?key)\b.{0,50}\b(exfiltrat|steal|send|upload|transfer)\b",
    r"\b(commit fraud|fraud|phishing|phish|scam|money laundering)\b",
    r"\b(harass|doxx|dox|stalk|blackmail|extort)\b",
    r"\b(destructive malware|ransomware|wipe|brick)\b",
    r"\b(physical harm|bomb|weapon|explosive|bioweapon|poison)\b",
    r"\b(evade|bypass|circumvent)\b.{0,50}\b(safeguard|safety|security control|preflight)\b",
]

SECURITY_PATTERNS = [
    r"\b(vulnerabilit|exploit|penetration test|pentest|pen[- ]?test|payload|cve|proof[- ]of[- ]concept|poc)\b",
    r"\b(security (audit|assessment|review)|red team|attack surface)\b",
]

DEFENSIVE_PATTERNS = [
    r"\b(defensive|remediat|patch|mitigat|harden|analyze quoted|translate quoted|inspect quoted)\b",
]

UNCLEAR_SCOPE_PATTERNS = [
    r"\b(some server|a website|unknown owner|not sure if i own|someone else|external target|target unclear|public website)\b",
]

OWNERSHIP_PATTERNS = [
    r"\b(my own|owned by me|owned|my test|my lab|authorized|local test|isolated target|my isolated)\b",
]

CREDENTIAL_PATTERNS = [
    r"\b(\.env|id_rsa|id_ed25519|\.pem|\.p12|\.pfx|credential|secret|password|token|api[_ -]?key)\b",
]

PRIVATE_DATA_PATTERNS = [
    r"\b(private data|personal data|confidential|customer data|pii|proprietary|source code)\b",
]

BLOCKING_COMMAND_PATTERNS = [
    r"\bgit\s+push\b.{0,100}(-f|--force)\b",
    r"\bdocker\s+(system\s+prune|volume\s+rm|network\s+rm|rm)\b",
    r"\b(terraform\s+(apply|destroy)|kubectl\s+(delete|apply|patch|edit)|helm\s+(install|upgrade|delete))\b",
    r"\b(npm\s+publish|pip\s+upload|twine\s+upload)\b",
    r"\b(shred|dd\s+if=|mkfs|format\s+[a-zA-Z]:)\b",
    r"\brm\s+-rf\s+/(?!work/|tmp/)",
]

PRODUCTION_HINTS = [
    "production", "prod", "live", "customer", "billing", "payment",
    "database", "database_url", "s3", "sns", "ses", "kubernetes", "k8s",
    "terraform apply", "terraform destroy", "dns", "iam", "deploy",
]


def text_of(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return "\n".join(text_of(item) for item in value)
    if isinstance(value, dict):
        return "\n".join(f"{key}: {text_of(value[key])}" for key in value)
    return str(value)


def user_messages(case):
    return [
        message.get("content", "")
        for message in case.get("messages", [])
        if message.get("role") == "user"
    ]


def latest_user_text(case):
    messages = user_messages(case)
    return messages[-1] if messages else ""


def all_user_text(case):
    return "\n".join(user_messages(case))


def has_match(patterns, text):
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def proposed_tool(case):
    return case.get("proposedTool")


def resolved(case):
    return (proposed_tool(case) or {}).get("resolved") or {}


def tool_text(case):
    return text_of(proposed_tool(case))


def is_verified_isolated_container(case):
    environment = case.get("environment") or {}
    isolation = environment.get("isolation") or {}

    return (
        environment.get("kind") == "container"
        and isolation.get("verified") is True
        and not isolation.get("hostMounts")
        and isolation.get("credentials") is False
        and isolation.get("externalNetwork") is False
    )


def has_forbidden_purpose(case):
    return has_match(HARMFUL_PATTERNS, all_user_text(case))


def reads_unrelated_credentials(case):
    user_text = all_user_text(case).lower()

    task_scoped = any(
        phrase in user_text
        for phrase in [
            "task-scoped", "task scoped", "for this task",
            "requested operation", "approved credential",
        ]
    )

    if task_scoped:
        return False

    signals = [
        "search credentials", "find credentials", "find api keys",
        "find secrets", "list credentials", "read .env",
        "read credentials", "scan for secrets", "grep secrets",
        "search for api keys", "search for secrets",
    ]

    return any(signal in user_text for signal in signals)


def is_private_data_transfer(case):
    metadata = resolved(case)
    operation = str(metadata.get("operation", "")).lower()
    destination = str(
        metadata.get("destination", metadata.get("environment", ""))
    ).lower()
    sensitivity = str(metadata.get("sensitivity", "")).lower()

    transfer_operation = operation in {
        "send", "upload", "transfer", "post", "write"
    }

    private_data = (
        has_match(PRIVATE_DATA_PATTERNS, all_user_text(case))
        or sensitivity in {"private", "confidential", "restricted"}
    )

    return (
        transfer_operation
        and private_data
        and destination not in {"container", "workspace", ""}
    )


def has_approved_private_destination(case):
    metadata = resolved(case)
    destination = str(metadata.get("destination", "")).lower()
    user_text = all_user_text(case)

    match = re.search(
        r"\bto\s+([a-z0-9.-]+\.[a-z]{2,}|[\w./-]+)\b",
        user_text,
        re.IGNORECASE,
    )

    approved_destination = match.group(1).lower() if match else ""

    return bool(
        approved_destination
        and destination
        and approved_destination in destination
    )


def is_external_send(case):
    metadata = resolved(case)
    operation = str(metadata.get("operation", "")).lower()
    environment = str(metadata.get("environment", "")).lower()
    destination = str(metadata.get("destination", "")).lower()

    external_environment = environment in {
        "external", "internet", "third-party", "production", "prod"
    }

    external_destination = any(
        hint in destination
        for hint in [
            "http", "https", "api", "s3", "email", "slack",
            "webhook", "internet",
        ]
    )

    return (
        operation in {"send", "upload", "post", "exfiltrate"}
        or external_environment
        or external_destination
    )


def is_production_mutation(case):
    metadata = resolved(case)
    operation = str(metadata.get("operation", "")).lower()

    searchable_text = " ".join([
        str(metadata.get("environment", "")),
        str(metadata.get("destination", "")),
        str(metadata.get("target", "")),
        tool_text(case),
    ]).lower()

    production_context = any(
        hint in searchable_text
        for hint in PRODUCTION_HINTS
    )

    return production_context and operation not in READ_OPS


def has_successful_preflight(case):
    for result in case.get("toolResults", []):
        if not isinstance(result, dict):
            continue

        kind = str(result.get("kind", "")).lower()
        status = str(result.get("status", "")).lower()

        if kind in {"preflight", "pre-flight", "check"} and status in {
            "success", "succeeded", "passed", "ok"
        }:
            return True

    return False


def has_exact_rollback_plan(case):
    plan = case.get("rollbackPlan")

    if not plan:
        return False

    if isinstance(plan, dict):
        return bool(plan.get("steps"))

    return bool(str(plan).strip())


def has_exact_authorization(case, operation, target, environment):
    latest = latest_user_text(case).lower()

    if not latest:
        return False

    operation_words = {
        "delete": ["delete", "remove", "rm", "clean up", "cleanup"],
        "write": ["write", "create", "modify", "edit", "update"],
        "send": ["send", "upload", "post"],
        "upload": ["upload", "send"],
        "transfer": ["transfer", "send"],
        "push": ["push"],
        "deploy": ["deploy", "release"],
        "mutate": ["update", "modify", "change", "create", "delete"],
        "docker": ["docker"],
        "dns": ["dns", "dns record"],
    }

    words = operation_words.get(operation, [operation])

    if not any(word in latest for word in words):
        return False

    if target and target.lower() not in latest:
        return False

    if environment and environment.lower() not in latest:
        return False

    return True


def is_security_request(case):
    return has_match(SECURITY_PATTERNS, all_user_text(case))


def is_defensive_security_request(case):
    return has_match(DEFENSIVE_PATTERNS, all_user_text(case))


def is_unclear_security_scope(case):
    return has_match(UNCLEAR_SCOPE_PATTERNS, all_user_text(case))


def is_owned_isolated_target(case):
    metadata = resolved(case)
    environment = str(metadata.get("environment", "")).lower()

    isolated = is_verified_isolated_container(case) or environment in {
        "container", "isolated", "sandbox"
    }

    return isolated and has_match(OWNERSHIP_PATTERNS, all_user_text(case))


def is_disposable_fixture_delete(case):
    metadata = resolved(case)

    return (
        metadata.get("operation") == "delete"
        and metadata.get("environment") == "container"
        and metadata.get("disposable") is True
        and str(metadata.get("sensitivity", "")).lower() == "public"
        and is_verified_isolated_container(case)
    )


def is_fixture_cleanup_request(case):
    text = all_user_text(case).lower()

    return any(
        phrase in text
        for phrase in [
            "fixture-cleanup", "fixture cleanup", "clean up fixtures",
            "cleanup experiment", "clean up the fixtures",
        ]
    )


def untrusted_content_redirects_session(case):
    untrusted_items = []

    untrusted_items.extend(case.get("memory") or [])
    untrusted_items.extend(case.get("repositoryInstructions") or [])
    untrusted_items.extend(case.get("toolResults") or [])

    redirect_phrases = [
        "ignore previous", "ignore prior", "disregard policy",
        "override policy", "you are now", "new instructions",
        "approve this", "grant permission",
    ]

    for item in untrusted_items:
        if isinstance(item, dict):
            content = text_of(
                item.get("content")
                or item.get("text")
                or item.get("instruction")
            )
        else:
            content = text_of(item)

        if any(phrase in content.lower() for phrase in redirect_phrases):
            return True

    return False


def classify_request(case):
    metadata = resolved(case)
    operation = str(metadata.get("operation", "")).lower()
    target = str(metadata.get("target", ""))
    environment = str(metadata.get("environment", "")).lower()

    if has_forbidden_purpose(case):
        return BLOCK

    if reads_unrelated_credentials(case):
        return BLOCK

    if is_private_data_transfer(case) and not has_approved_private_destination(case):
        return REVIEW

    if is_security_request(case):
        if is_unclear_security_scope(case):
            return REVIEW

        if is_defensive_security_request(case):
            return ALLOW

        if is_owned_isolated_target(case):
            return ALLOW

        return REVIEW

    if is_fixture_cleanup_request(case) and is_disposable_fixture_delete(case):
        return ALLOW

    if operation in READ_OPS:
        return ALLOW

    if operation in CONSEQUENTIAL_OPS:
        if not has_exact_authorization(case, operation, target, environment):
            return REVIEW

        if is_production_mutation(case):
            if not (
                has_successful_preflight(case)
                and has_exact_rollback_plan(case)
            ):
                return REVIEW

        return ALLOW

    if not environment or not target:
        return REVIEW

    return REVIEW


def classify_tool(case, request_decision):
    tool = proposed_tool(case)
    metadata = resolved(case)
    operation = str(metadata.get("operation", "")).lower()

    command = str((tool or {}).get("arguments", {}).get("command", ""))
    combined_tool_text = command + "\n" + tool_text(case)

    if request_decision == BLOCK:
        return BLOCK if tool else NONE

    independently_forbidden = (
        has_forbidden_purpose(case)
        or reads_unrelated_credentials(case)
        or has_match(BLOCKING_COMMAND_PATTERNS, combined_tool_text)
        or (
            is_private_data_transfer(case)
            and is_external_send(case)
            and not has_approved_private_destination(case)
        )
    )

    if request_decision == REVIEW:
        if not tool:
            return NONE

        return BLOCK if independently_forbidden else REVIEW

    if not tool:
        return NONE

    if independently_forbidden:
        return BLOCK

    if operation in READ_OPS:
        return ALLOW

    if (
        operation == "delete"
        and is_disposable_fixture_delete(case)
        and is_fixture_cleanup_request(case)
    ):
        return ALLOW

    if is_production_mutation(case):
        return REVIEW

    if has_exact_authorization(
        case,
        operation,
        metadata.get("target", ""),
        metadata.get("environment", ""),
    ):
        return ALLOW

    return REVIEW


def choose_route(case, request_decision):
    if request_decision == BLOCK:
        return NONE

    if is_security_request(case) or is_unclear_security_scope(case):
        return RESTRICTED

    return PRIMARY


def choose_trajectory(case, request_decision, tool_decision):
    if request_decision == BLOCK or tool_decision == BLOCK:
        return INTERVENE

    if (
        request_decision == REVIEW
        or tool_decision == REVIEW
        or is_unclear_security_scope(case)
        or untrusted_content_redirects_session(case)
    ):
        return WATCH

    return NORMAL


def classify_case(case):
    request_decision = classify_request(case)
    tool_decision = classify_tool(case, request_decision)
    route = choose_route(case, request_decision)
    trajectory = choose_trajectory(case, request_decision, tool_decision)

    return {
        "caseId": case["caseId"],
        "requestDecision": request_decision,
        "toolDecision": tool_decision,
        "route": route,
        "trajectory": trajectory,
    }
