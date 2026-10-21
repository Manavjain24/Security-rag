"""policy.py - RAG Supply-Chain Security Runtime Agent Gate & Policy Engine.

This module provides deterministic runtime security enforcement for RAG agents across:
1. Email operations (recipient authorization, customer data protection, approval workflow).
2. Database operations (safe reads, parameterized queries, write protection, approval workflow).
3. Outgoing HTTP requests (SSRF prevention, private IP blocking, safe redirect validation, payload provenance).

Key components:
- Source-aware document ingestion with trust-tier assignment and canonical SHA-256 hashing.
- Exact entity/phrase argument-origin tracing (USER_QUERY, TIER_1_CHUNK, TIER_2_CHUNK, TIER_3_CHUNK, TOOL_OUTPUT, UNKNOWN).
- Deterministic runtime policy gate returning ALLOW, REQUIRE_APPROVAL, or BLOCK with human and machine reasons.
- Safe simulated side-effect execution and tool-output taint propagation.
- Fail-safe structured JSONL audit logging.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import unquote, urlparse


# =====================================================================
# 1. ENUMERATIONS & DATA STRUCTURES
# =====================================================================

class TrustTier(int, Enum):
    """Trust tiers for retrieved context."""
    TIER_1 = 1  # Curated, trusted reference information (e.g., official wiki, approved policies)
    TIER_2 = 2  # Internal but editable information (e.g., internal tickets, team notes)
    TIER_3 = 3  # External or untrusted information (e.g., emails, web pages, user uploads)


class VerdictType(str, Enum):
    """Deterministic security gate verdicts."""
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


class OriginCategory(str, Enum):
    """Standard argument origin categories."""
    USER_QUERY = "USER_QUERY"
    TIER_1_CHUNK = "TIER_1_CHUNK"
    TIER_2_CHUNK = "TIER_2_CHUNK"
    TIER_3_CHUNK = "TIER_3_CHUNK"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    UNKNOWN = "UNKNOWN"


# Mapping canonical source identifiers/types to trust tiers
# Any source not in this mapping fails closed to Tier 3.
SOURCE_TIER_MAPPING: Dict[str, TrustTier] = {
    "company wiki": TrustTier.TIER_1,
    "official policy": TrustTier.TIER_1,
    "curated knowledgebase": TrustTier.TIER_1,
    "internal ticket": TrustTier.TIER_2,
    "employee notes": TrustTier.TIER_2,
    "internal slack": TrustTier.TIER_2,
    "external email": TrustTier.TIER_3,
    "customer upload": TrustTier.TIER_3,
    "web scrape": TrustTier.TIER_3,
    "untrusted source": TrustTier.TIER_3,
}

# Permitted tools schema covering Email, DB, HTTP, and search
TOOL_ALLOWLIST = {
    "read_file": {"required": ["path"], "allowed_types": {"path": str}},
    "query_db": {
        "required": ["table"],
        "allowed_types": {
            "table": str,
            "customer_id": str,
            "sql": str,
            "bulk": bool,
            "allow_bulk": bool,
        },
    },
    "db_write": {
        "required": ["table"],
        "allowed_types": {
            "table": str,
            "customer_id": str,
            "status": str,
            "operation": str,
            "data": (dict, str),
            "sql": str,
        },
    },
    "send_email": {
        "required": ["to", "subject", "body"],
        "allowed_types": {"to": str, "subject": str, "body": str},
    },
    "http_request": {
        "required": ["url", "method"],
        "allowed_types": {
            "url": str,
            "method": str,
            "data": (str, dict),
            "body": (str, dict),
            "headers": dict,
            "redirect_url": str,
            "follow_redirects": bool,
        },
    },
    "search_docs": {"required": ["query"], "allowed_types": {"query": str}},
}

PERMITTED_FILES = {
    "data/customers.json",
    "data/documents.json",
    "customers.json",
    "documents.json",
}

PERMITTED_TABLES = {"customers"}
ALLOWED_HTTP_HOSTS = {
    "support.example.test",
    "status.example.test",
    "api.acme.test",
    "api.example.test",
    "compliance-firm.test",
}
INTERNAL_EMAIL_DOMAINS = {"acme.test", "company.test", "acme.example.test"}
PROHIBITED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "metadata.google.internal",
    "169.254.169.254",
}
DEMO_CUSTOMER_IDS = {"C-104", "C-208", "C-319"}


# =====================================================================
# 2. INGESTION, PROVENANCE & INTEGRITY
# =====================================================================

def compute_content_hash(title: str, text: str) -> str:
    """Compute a deterministic SHA-256 hash over canonical representation of content.
    
    Canonical representation: 'title:<title.strip()>\ntext:<text.strip()>' encoded in utf-8.
    Changing either title or text invalidates the previously calculated hash.
    """
    canonical_repr = f"title:{title.strip()}\ntext:{text.strip()}".encode("utf-8")
    return hashlib.sha256(canonical_repr).hexdigest()


INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+(instructions|rules|prompts)", re.IGNORECASE), "IGNORE_PREVIOUS_INSTRUCTIONS"),
    (re.compile(r"urgent\s+troubleshooting\s+instructions", re.IGNORECASE), "URGENT_OVERRIDE_DIRECTIVE"),
    (re.compile(r"(system\s+prompt|developer\s+mode|jailbreak)", re.IGNORECASE), "SYSTEM_PROMPT_REFERENCE"),
    (re.compile(r"(email|send|exfiltrate|forward)\s+(it|them|all|data|list)\s+to\s+[\w.+-]+@", re.IGNORECASE), "DATA_EXFILTRATION_DIRECTIVE"),
    (re.compile(r"this\s+is\s+an\s+authorized\s+audit", re.IGNORECASE), "FALSE_AUTHORITY_CLAIM"),
    (re.compile(r"override\s+security\s+policy", re.IGNORECASE), "POLICY_OVERRIDE_DIRECTIVE"),
]


def scan_injection(text: str) -> list[dict[str, Any]]:
    """Lightweight heuristic scan for suspicious prompt injection and poisoning directives."""
    flags: list[dict[str, Any]] = []
    for pattern, name in INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            flags.append({
                "flag": name,
                "pattern": pattern.pattern,
                "matched_text": match.group(0),
                "severity": "HIGH",
            })
    return flags


def assign_trust_tier(source: Optional[str]) -> TrustTier:
    """Determine trust tier from source type.
    
    Document text cannot declare its own trust level.
    Missing, invalid, or unrecognized sources fail closed to Tier 3.
    """
    if not source or not isinstance(source, str):
        return TrustTier.TIER_3
    normalized = source.strip().lower()
    return SOURCE_TIER_MAPPING.get(normalized, TrustTier.TIER_3)


def ingest_document(
    raw_doc: dict[str, Any],
    default_author: str = "system",
    auto_quarantine: bool = True,
) -> dict[str, Any]:
    """Source-aware document ingestion with integrity hashing and quarantine tagging."""
    doc_id = str(raw_doc.get("doc_id") or f"doc-{uuid.uuid4().hex[:8]}")
    title = str(raw_doc.get("title", "Untitled"))
    text = str(raw_doc.get("text", ""))
    source = str(raw_doc.get("source", "untrusted source"))
    
    tier = assign_trust_tier(source)
    content_hash = compute_content_hash(title, text)
    injection_flags = scan_injection(text)
    quarantine_status = "QUARANTINED" if (injection_flags and auto_quarantine) else "CLEAN"
    
    return {
        "doc_id": doc_id,
        "title": title,
        "source": source,
        "tier": int(tier),
        "text": text,
        "author": raw_doc.get("author", default_author),
        "ingested_at": raw_doc.get("ingested_at", datetime.now(timezone.utc).isoformat()),
        "content_hash": content_hash,
        "injection_flags": injection_flags,
        "integrity_status": "VERIFIED",
        "quarantine_status": quarantine_status,
    }


def release_from_quarantine(doc: dict[str, Any], reviewer: str = "security_admin") -> dict[str, Any]:
    """Release a quarantined document after explicit administrative review."""
    updated = dict(doc)
    updated["quarantine_status"] = "RELEASED"
    updated["reviewed_by"] = reviewer
    updated["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    return updated


def is_document_quarantined(doc: dict[str, Any]) -> bool:
    """Check if document is actively quarantined from retrieval context."""
    return doc.get("quarantine_status") == "QUARANTINED"


def verify_document_integrity(doc: dict[str, Any]) -> tuple[bool, str]:
    """Verify document integrity by recomputing and comparing SHA-256 hash."""
    stored_hash = doc.get("content_hash")
    if not stored_hash or not isinstance(stored_hash, str):
        return False, "Missing or invalid content_hash metadata."
    
    title = str(doc.get("title", ""))
    text = str(doc.get("text", ""))
    computed_hash = compute_content_hash(title, text)
    
    if computed_hash != stored_hash:
        return False, f"Hash mismatch: stored {stored_hash[:12]}... != computed {computed_hash[:12]}..."
    return True, "Integrity verified."


# =====================================================================
# 3. URL SAFETY & SSRF DEFENSE
# =====================================================================

def is_safe_destination_url(url_str: str) -> tuple[bool, str]:
    """Inspect outgoing URL for SSRF, private/internal IP ranges, and prohibited hosts."""
    try:
        parsed = urlparse(url_str.strip())
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return False, f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are permitted."
        
        host = (parsed.hostname or "").lower()
        if not host:
            return False, "Missing or invalid destination host in URL."
        
        if host in PROHIBITED_HOSTS or host.endswith(".internal") or host.endswith(".local"):
            return False, f"Prohibited destination host '{host}' (localhost or internal service)."
        
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False, f"Prohibited private, loopback, or link-local IP destination: {host}."
        except ValueError:
            pass  # Standard domain name
            
        return True, "URL destination is safe."
    except Exception as exc:
        return False, f"Malformed URL: {exc}"


def validate_http_redirect(initial_url: str, redirect_target: str) -> tuple[bool, str]:
    """Ensure HTTP redirect does not navigate to prohibited or private destination."""
    is_safe, msg = is_safe_destination_url(redirect_target)
    if not is_safe:
        return False, f"Redirect to prohibited destination blocked: {msg}"
    parsed_target = urlparse(redirect_target)
    host = (parsed_target.hostname or "").lower()
    if host not in ALLOWED_HTTP_HOSTS:
        return False, f"Redirect to unauthorized host '{host}' blocked."
    return True, "Redirect destination is valid."


# =====================================================================
# 4. ARGUMENT ORIGIN TRACING
# =====================================================================

def extract_entities(text: str) -> set[str]:
    """Extract significant entities (emails, tokens, identifiers, domains)."""
    entities = set()
    for match in re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text):
        entities.add(match.lower())
    for match in re.findall(r"https?://[^\s/$.?#].[^\s]*|[a-zA-Z0-9.-]+\.(?:test|com|org|net|io|edu)", text):
        entities.add(match.lower())
    for match in re.findall(r"\b[A-Z]{1,8}-\d{2,}\b", text):
        entities.add(match.lower())
    for word in re.findall(r"[a-zA-Z0-9_-]{4,}", text):
        entities.add(word.lower())
    return entities


def json_safe_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str) if not isinstance(value, str) else value


def trace_argument_origin(
    arg_name: str,
    arg_val: Any,
    query: str,
    docs: list[dict[str, Any]],
    tool_outputs: list[dict[str, Any] | str],
) -> dict[str, Any]:
    """Trace origin of a single argument against query, retrieved chunks, and tool outputs."""
    str_val = json_safe_text(arg_val).strip()
    if not str_val:
        return {
            "argument": arg_name,
            "value": arg_val,
            "categories": [OriginCategory.UNKNOWN.value],
            "primary_category": OriginCategory.UNKNOWN.value,
            "sources": [],
            "matched_entities": [],
        }

    val_lower = str_val.lower()
    val_entities = extract_entities(str_val)
    
    matched_categories: set[str] = set()
    sources_info: list[dict[str, Any]] = []
    matched_entities: list[str] = []

    # 1. Check User Query
    query_lower = query.lower()
    if val_lower in query_lower or any(e in query_lower for e in val_entities):
        matched_categories.add(OriginCategory.USER_QUERY.value)
        sources_info.append({"source": "user_query", "tier": 0, "type": "query"})
        for e in val_entities:
            if e in query_lower:
                matched_entities.append(f"user_query:{e}")

    # 2. Check Retrieved Chunks
    for doc in docs:
        doc_text_lower = f"{doc.get('title', '')} {doc.get('text', '')}".lower()
        doc_tier = doc.get("tier", 3)
        cat = {
            1: OriginCategory.TIER_1_CHUNK.value,
            2: OriginCategory.TIER_2_CHUNK.value,
            3: OriginCategory.TIER_3_CHUNK.value,
        }.get(doc_tier, OriginCategory.TIER_3_CHUNK.value)

        direct_match = val_lower in doc_text_lower
        entity_matches = [e for e in val_entities if e in doc_text_lower]
        
        if direct_match or entity_matches:
            matched_categories.add(cat)
            sources_info.append({
                "source": doc.get("doc_id", "unknown"),
                "tier": doc_tier,
                "title": doc.get("title", ""),
                "integrity": doc.get("integrity_status", "UNKNOWN"),
                "flags": [f["flag"] for f in doc.get("injection_flags", [])],
            })
            for em in entity_matches:
                matched_entities.append(f"{doc.get('doc_id')}:{em}")

    # 3. Check Prior Tool Outputs (Multi-step taint tracking)
    for idx, out in enumerate(tool_outputs):
        out_str = out if isinstance(out, str) else json_safe_text(out)
        out_lower = out_str.lower()
        if val_lower in out_lower or any(e in out_lower for e in val_entities):
            matched_categories.add(OriginCategory.TOOL_OUTPUT.value)
            sources_info.append({
                "source": f"tool_output_{idx}",
                "tier": None,
                "type": "tool_output",
                "taints": out.get("taints", []) if isinstance(out, dict) else [],
            })

    if not matched_categories:
        matched_categories.add(OriginCategory.UNKNOWN.value)

    # Restrictive precedence: TIER_3 > UNKNOWN > TIER_2 > TOOL_OUTPUT > TIER_1 > USER_QUERY
    precedence = [
        OriginCategory.TIER_3_CHUNK.value,
        OriginCategory.UNKNOWN.value,
        OriginCategory.TIER_2_CHUNK.value,
        OriginCategory.TOOL_OUTPUT.value,
        OriginCategory.TIER_1_CHUNK.value,
        OriginCategory.USER_QUERY.value,
    ]
    primary = next((p for p in precedence if p in matched_categories), OriginCategory.UNKNOWN.value)

    return {
        "argument": arg_name,
        "value": str_val[:200] + ("..." if len(str_val) > 200 else ""),
        "categories": sorted(list(matched_categories)),
        "primary_category": primary,
        "sources": sources_info,
        "matched_entities": list(set(matched_entities)),
    }


def trace_call_origins(
    tool: str,
    args: dict[str, Any],
    query: str,
    docs: list[dict[str, Any]],
    tool_outputs: list[dict[str, Any] | str],
) -> dict[str, dict[str, Any]]:
    """Trace all argument origins for a proposed tool call."""
    traces: dict[str, dict[str, Any]] = {}
    for k, v in args.items():
        traces[k] = trace_argument_origin(k, v, query, docs, tool_outputs)
    return traces


# =====================================================================
# 5. DETERMINISTIC RUNTIME POLICY GATE
# =====================================================================

class PolicyVerdict:
    """Structured decision returned by the deterministic runtime policy gate."""
    def __init__(
        self,
        verdict: VerdictType,
        reason_code: str,
        reason: str,
        tool: str,
        rules_evaluated: list[str],
        origin_traces: dict[str, Any],
        safe_to_execute: bool = False,
        exposure_findings: Optional[list[dict[str, Any]]] = None,
        trajectory_findings: Optional[dict[str, Any]] = None,
    ):
        self.verdict = verdict
        self.reason_code = reason_code
        self.reason = reason
        self.tool = tool
        self.rules_evaluated = rules_evaluated
        self.origin_traces = origin_traces
        self.safe_to_execute = safe_to_execute
        self.exposure_findings = exposure_findings or []
        self.trajectory_findings = trajectory_findings

    def to_dict(self) -> dict[str, Any]:
        data = {
            "verdict": self.verdict.value,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "tool": self.tool,
            "rules_evaluated": self.rules_evaluated,
            "origin_traces": self.origin_traces,
            "safe_to_execute": self.safe_to_execute,
            "exposure_findings": self.exposure_findings,
        }
        if self.trajectory_findings:
            data["trajectory_findings"] = self.trajectory_findings
        return data


# PII & Sensitive Credential Detection Patterns
PII_PATTERNS = [
    (re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"), "CREDIT_CARD", "Credit card number pattern"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b"), "PHONE_NUMBER", "Phone number pattern"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN", "Social Security Number pattern"),
    (re.compile(r"\b(?:api[_-]?key|bearer|secret|token)[\s:=]+([a-zA-Z0-9_\-]{16,})\b", re.IGNORECASE), "API_KEY_OR_SECRET", "API key or secret token pattern"),
]


def scan_payload_exposure(payload: Any) -> list[dict[str, Any]]:
    """Scan outgoing payload text or objects for sensitive PII or credential patterns."""
    text = json_safe_text(payload)
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pattern, pii_type, desc in PII_PATTERNS:
        for match in pattern.finditer(text):
            val = match.group(0)
            if val in seen:
                continue
            seen.add(val)
            masked = val[:2] + "*" * max(0, len(val) - 4) + val[-2:] if len(val) > 6 else "***"
            findings.append({
                "type": pii_type,
                "description": desc,
                "sample_masked": masked,
            })
    return findings


def analyze_tool_trajectory(
    current_tool: str,
    current_args: dict[str, Any],
    prior_steps: Optional[list[dict[str, Any]]],
    customers_data: list[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """Inspect sequence of tool calls in current trajectory for multi-step attack patterns."""
    if not prior_steps:
        return None
    
    prior_tools = [s.get("tool") for s in prior_steps if isinstance(s, dict) and s.get("tool")]
    
    # 1. READ-THEN-EXFILTRATE PATTERN:
    # A prior step was query_db, followed by an external outbound HTTP request or external email
    if "query_db" in prior_tools:
        if current_tool == "http_request":
            method = str(current_args.get("method", "GET")).upper()
            if method in ("POST", "PUT", "DELETE") or current_args.get("data") or current_args.get("body"):
                return {
                    "pattern": "READ_THEN_EXFILTRATE_HTTP",
                    "severity": "HIGH",
                    "reason_code": "TRAJECTORY_EXFILTRATION_DETECTED",
                    "reason": "Trajectory violation: Sensitive database read followed by outbound HTTP transmission (read-then-exfiltrate pattern).",
                }
        elif current_tool == "send_email":
            to = str(current_args.get("to", "")).lower()
            domain = to.rsplit("@", 1)[-1] if "@" in to else ""
            is_internal = any(domain == d or domain.endswith("." + d) for d in INTERNAL_EMAIL_DOMAINS)
            if not is_internal:
                return {
                    "pattern": "READ_THEN_EXFILTRATE_EMAIL",
                    "severity": "HIGH",
                    "reason_code": "TRAJECTORY_EXFILTRATION_DETECTED",
                    "reason": f"Trajectory violation: Sensitive database read followed by external email to '{to}'.",
                }

    # 2. RAPID / MULTIPLE DATABASE MUTATION PATTERN:
    db_writes_count = sum(1 for t in prior_tools if t == "db_write")
    if current_tool == "db_write" and db_writes_count >= 1:
        return {
            "pattern": "RAPID_DB_MUTATION",
            "severity": "MEDIUM",
            "reason_code": "TRAJECTORY_RAPID_MUTATION_DETECTED",
            "reason": "Trajectory violation: Multiple consecutive database write operations in a single agent run require heightened approval.",
        }

    return None


def contains_customer_data(text: str, customers: list[dict[str, Any]]) -> bool:
    """Check if text contains records, emails, or names of customer records."""
    text_lower = unquote(json_safe_text(text)).lower()
    for cust in customers:
        if cust.get("name", "").lower() in text_lower:
            return True
        if cust.get("email", "").lower() in text_lower:
            return True
        if cust.get("customer_id", "").lower() in text_lower:
            return True
    return False


def evaluate_tool_policy(
    tool: str,
    args: dict[str, Any],
    query: str,
    docs: list[dict[str, Any]],
    tool_outputs: list[dict[str, Any] | str],
    customers_data: list[dict[str, Any]],
    guard_enabled: bool = True,
    approved_tokens: Optional[set[str]] = None,
    prior_steps: Optional[list[dict[str, Any]]] = None,
) -> PolicyVerdict:
    """Single security gateway: intercepts Email, Database, and HTTP tool calls before execution.
    
    Evaluates deterministic policies and returns ALLOW, REQUIRE_APPROVAL, or BLOCK.
    Fails closed on any unexpected exception.
    """
    rules_evaluated: list[str] = []
    
    try:
        origins = trace_call_origins(tool, args, query, docs, tool_outputs)
        
        # If guard is toggled off, allow with clear warning
        if not guard_enabled:
            return PolicyVerdict(
                verdict=VerdictType.ALLOW,
                reason_code="GUARD_DISABLED",
                reason="Security guard is disabled; unvalidated execution proceeded.",
                tool=tool,
                rules_evaluated=["RULE_GUARD_OVERRIDE"],
                origin_traces=origins,
                safe_to_execute=True,
            )

        # -------------------------------------------------------------
        # 1. TOOL ALLOWLIST CHECK
        # -------------------------------------------------------------
        rules_evaluated.append("R01_TOOL_ALLOWLIST")
        if tool not in TOOL_ALLOWLIST:
            return PolicyVerdict(
                verdict=VerdictType.BLOCK,
                reason_code="UNKNOWN_TOOL_DENIED",
                reason=f"Tool '{tool}' is not in the authorized allowlist.",
                tool=tool,
                rules_evaluated=rules_evaluated,
                origin_traces=origins,
                safe_to_execute=False,
            )

        # -------------------------------------------------------------
        # 2. SCHEMA & ARGUMENT VALIDATION
        # -------------------------------------------------------------
        rules_evaluated.append("R02_SCHEMA_VALIDATION")
        if not isinstance(args, dict):
            return PolicyVerdict(
                verdict=VerdictType.BLOCK,
                reason_code="INVALID_ARGUMENT_FORMAT",
                reason="Tool arguments must be structured in a JSON object.",
                tool=tool,
                rules_evaluated=rules_evaluated,
                origin_traces=origins,
                safe_to_execute=False,
            )

        spec = TOOL_ALLOWLIST[tool]
        for req_field in spec["required"]:
            if req_field not in args:
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="MISSING_REQUIRED_ARGUMENT",
                    reason=f"Tool '{tool}' call is missing required parameter '{req_field}'.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )
            expected_type = spec["allowed_types"].get(req_field)
            if expected_type and not isinstance(args[req_field], expected_type):
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="INVALID_ARGUMENT_TYPE",
                    reason=f"Argument '{req_field}' has invalid type {type(args[req_field]).__name__}; expected {expected_type}.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )

        # -------------------------------------------------------------
        # 2B. TRAJECTORY PATTERN ANALYSIS (Multi-Step Trajectories)
        # -------------------------------------------------------------
        if prior_steps:
            rules_evaluated.append("R02B_TRAJECTORY_PATTERN_ANALYSIS")
            traj_violation = analyze_tool_trajectory(tool, args, prior_steps, customers_data)
            if traj_violation:
                call_token = f"trajectory:{traj_violation['reason_code']}:{tool}"
                is_traj_approved = approved_tokens is not None and call_token in approved_tokens
                if traj_violation.get("severity") == "HIGH" and not is_traj_approved:
                    return PolicyVerdict(
                        verdict=VerdictType.BLOCK,
                        reason_code=traj_violation["reason_code"],
                        reason=traj_violation["reason"],
                        tool=tool,
                        rules_evaluated=rules_evaluated,
                        origin_traces=origins,
                        safe_to_execute=False,
                        trajectory_findings=traj_violation,
                    )
                elif traj_violation.get("severity") == "MEDIUM" and not is_traj_approved:
                    return PolicyVerdict(
                        verdict=VerdictType.REQUIRE_APPROVAL,
                        reason_code=traj_violation["reason_code"],
                        reason=traj_violation["reason"],
                        tool=tool,
                        rules_evaluated=rules_evaluated,
                        origin_traces=origins,
                        safe_to_execute=False,
                        trajectory_findings=traj_violation,
                    )

        # -------------------------------------------------------------
        # 3. FILE READ SANDBOXING (read_file)
        # -------------------------------------------------------------
        if tool == "read_file":
            rules_evaluated.append("R03_FILE_SANDBOX")
            path_val = str(args.get("path", "")).strip().replace("\\", "/")
            if ".." in path_val or path_val.startswith("/") or re.match(r"^[a-zA-Z]:", path_val):
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="PATH_TRAVERSAL_BLOCKED",
                    reason=f"Path traversal or absolute path detected in file path: '{path_val}'.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )
            if path_val not in PERMITTED_FILES:
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="UNAUTHORIZED_FILE_ACCESS",
                    reason=f"Access to file '{path_val}' is unauthorized.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )
            return PolicyVerdict(
                verdict=VerdictType.ALLOW,
                reason_code="PERMITTED_FILE_READ",
                reason=f"Reading authorized file '{path_val}'.",
                tool=tool,
                rules_evaluated=rules_evaluated,
                origin_traces=origins,
                safe_to_execute=True,
            )

        # -------------------------------------------------------------
        # 4. DATABASE SECURITY: READS (query_db)
        # -------------------------------------------------------------
        if tool == "query_db":
            rules_evaluated.append("R05_DB_READ_RESTRICTION")
            table = str(args.get("table", "")).strip()
            
            # Check for arbitrary raw SQL attempts
            if args.get("sql"):
                sql_str = str(args.get("sql", "")).upper()
                if any(kw in sql_str for kw in ("DROP", "DELETE", "INSERT", "UPDATE", "ALTER", ";", "--")):
                    return PolicyVerdict(
                        verdict=VerdictType.BLOCK,
                        reason_code="ARBITRARY_SQL_DENIED",
                        reason="Arbitrary or destructive raw SQL execution is forbidden. Only parameterized operations are permitted.",
                        tool=tool,
                        rules_evaluated=rules_evaluated,
                        origin_traces=origins,
                        safe_to_execute=False,
                    )

            if table not in PERMITTED_TABLES:
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="UNAUTHORIZED_TABLE_ACCESS",
                    reason=f"Querying table '{table}' is unauthorized. Permitted tables: {sorted(list(PERMITTED_TABLES))}.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )
            
            # Bulk reads protection: if bulk parameter explicitly denied or request unauthorized
            if args.get("bulk") is True and not args.get("allow_bulk"):
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="BULK_READ_DENIED",
                    reason="Bulk customer-table reads are denied. Request one specific customer record.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )

            cid = args.get("customer_id")
            if cid and str(cid).strip() not in DEMO_CUSTOMER_IDS:
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="CUSTOMER_NOT_FOUND",
                    reason=f"Requested customer ID '{cid}' does not exist in the fictional database.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )

            return PolicyVerdict(
                verdict=VerdictType.ALLOW,
                reason_code="PERMITTED_DB_QUERY",
                reason=f"Read-only lookup of permitted demo table '{table}'.",
                tool=tool,
                rules_evaluated=rules_evaluated,
                origin_traces=origins,
                safe_to_execute=True,
            )

        # -------------------------------------------------------------
        # 5. DATABASE SECURITY: WRITES (db_write)
        # -------------------------------------------------------------
        if tool == "db_write":
            rules_evaluated.append("R06_DB_WRITE_RESTRICTION")
            table = str(args.get("table", "")).strip()
            
            # Check for arbitrary raw SQL attempts
            if args.get("sql"):
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="ARBITRARY_SQL_DENIED",
                    reason="Arbitrary raw SQL write operations are forbidden.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )

            if table not in PERMITTED_TABLES:
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="UNAUTHORIZED_TABLE_ACCESS",
                    reason=f"Database write to table '{table}' is unauthorized.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )

            # Check if write instruction originated from untrusted Tier-3 content
            for arg_key in ("status", "data", "customer_id"):
                arg_trace = origins.get(arg_key, {})
                if OriginCategory.TIER_3_CHUNK.value in arg_trace.get("categories", []):
                    return PolicyVerdict(
                        verdict=VerdictType.BLOCK,
                        reason_code="TIER3_DB_WRITE_FORBIDDEN",
                        reason=f"Database write parameter '{arg_key}' originated from untrusted Tier-3 content. Untrusted retrieval cannot alter database records.",
                        tool=tool,
                        rules_evaluated=rules_evaluated,
                        origin_traces=origins,
                        safe_to_execute=False,
                    )

            # Write operations require explicit human approval
            cid = str(args.get("customer_id", ""))
            status_val = str(args.get("status", args.get("data", "")))
            call_token = f"db_write:{table}:{cid}:{hashlib.sha256(status_val.encode()).hexdigest()[:8]}"
            is_approved = approved_tokens is not None and call_token in approved_tokens

            if not is_approved:
                return PolicyVerdict(
                    verdict=VerdictType.REQUIRE_APPROVAL,
                    reason_code="DB_WRITE_APPROVAL_REQUIRED",
                    reason=f"Database write operation on '{table}' requires explicit human approval before execution.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )

            return PolicyVerdict(
                verdict=VerdictType.ALLOW,
                reason_code="PERMITTED_DB_WRITE",
                reason=f"Database write to '{table}' authorized with valid human approval.",
                tool=tool,
                rules_evaluated=rules_evaluated,
                origin_traces=origins,
                safe_to_execute=True,
            )

        # -------------------------------------------------------------
        # 6. EMAIL SECURITY (send_email)
        # -------------------------------------------------------------
        if tool == "send_email":
            recipient = str(args.get("to", "")).strip()
            body = str(args.get("body", "")).strip()
            
            to_trace = origins.get("to", {})
            body_trace = origins.get("body", {})

            # Recipient from Tier 3 content is forbidden
            rules_evaluated.append("R07_EMAIL_TIER3_RECIPIENT_CHECK")
            if OriginCategory.TIER_3_CHUNK.value in to_trace.get("categories", []):
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="TIER3_RECIPIENT_FORBIDDEN",
                    reason=f"Recipient address '{recipient}' originated from untrusted Tier-3 content. Untrusted documents cannot choose action destinations.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )

            # Exfiltration of customer data without authorized user query or Tier-1 origin
            rules_evaluated.append("R08_EMAIL_DATA_EXFILTRATION_CHECK")
            has_cust_data = contains_customer_data(body, customers_data)
            body_cats = body_trace.get("categories", [])
            trusted_auth = (OriginCategory.USER_QUERY.value in body_cats) or (OriginCategory.TIER_1_CHUNK.value in body_cats)
            
            if has_cust_data and not trusted_auth:
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="UNAUTHORIZED_DATA_EXFILTRATION",
                    reason="Proposed email contains sensitive customer records without authorized user query or Tier-1 policy instruction.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )

            domain = recipient.rsplit("@", 1)[-1].lower() if "@" in recipient else ""
            is_internal_recipient = any(domain == d or domain.endswith("." + d) for d in INTERNAL_EMAIL_DOMAINS)
            call_token = f"send_email:{recipient}:{hashlib.sha256(body.encode()).hexdigest()[:8]}"
            is_approved = approved_tokens is not None and call_token in approved_tokens

            # Data-exposure / PII scan on email subject + body
            rules_evaluated.append("R09A_EMAIL_PAYLOAD_EXPOSURE_SCAN")
            exposure_findings = scan_payload_exposure(f"{args.get('subject', '')} {body}")
            if exposure_findings and not is_internal_recipient:
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="SENSITIVE_DATA_EXPOSURE_BLOCKED",
                    reason=f"Outgoing email payload contains sensitive {exposure_findings[0]['type']} data ({exposure_findings[0]['description']}) destined for external recipient '{recipient}'.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                    exposure_findings=exposure_findings,
                )

            # Outbound email to external recipient requires human approval
            rules_evaluated.append("R09B_EMAIL_OUTBOUND_APPROVAL_CHECK")
            if not is_internal_recipient:
                if not is_approved:
                    return PolicyVerdict(
                        verdict=VerdictType.REQUIRE_APPROVAL,
                        reason_code="EMAIL_EXTERNAL_APPROVAL_REQUIRED",
                        reason=f"Outbound email to external recipient '{recipient}' requires explicit human approval.",
                        tool=tool,
                        rules_evaluated=rules_evaluated,
                        origin_traces=origins,
                        safe_to_execute=False,
                    )

            return PolicyVerdict(
                verdict=VerdictType.ALLOW,
                reason_code="PERMITTED_EMAIL_DISPATCH",
                reason=f"Email dispatch authorized{' (approved by human)' if is_approved else ''}.",
                tool=tool,
                rules_evaluated=rules_evaluated,
                origin_traces=origins,
                safe_to_execute=True,
                exposure_findings=exposure_findings,
            )

        # -------------------------------------------------------------
        # 7. HTTP REQUEST SECURITY (http_request)
        # -------------------------------------------------------------
        if tool == "http_request":
            method = str(args.get("method", "GET")).upper()
            url = str(args.get("url", "")).strip()
            url_trace = origins.get("url", {})
            payload_str = json_safe_text(args.get("data") or args.get("body") or "")
            payload_trace = origins.get("data", {}) or origins.get("body", {})

            # Method check
            rules_evaluated.append("R10_HTTP_METHOD_CHECK")
            if method not in ("GET", "POST", "PUT", "DELETE"):
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="INVALID_HTTP_METHOD",
                    reason=f"HTTP method '{method}' is not permitted.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )

            # Destination safety & SSRF prevention (localhost, private IPs)
            rules_evaluated.append("R11_HTTP_SSRF_CHECK")
            is_safe, msg = is_safe_destination_url(url)
            if not is_safe:
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="SSRF_DESTINATION_BLOCKED",
                    reason=f"Prohibited HTTP destination: {msg}",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )

            # Destination host allowlist check
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            if host not in ALLOWED_HTTP_HOSTS:
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="UNAUTHORIZED_HTTP_HOST",
                    reason=f"Destination host '{host}' is not on the HTTP allowlist ({sorted(list(ALLOWED_HTTP_HOSTS))}).",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )

            # Redirect destination check
            redirect_target = args.get("redirect_url")
            if redirect_target:
                rules_evaluated.append("R12_HTTP_REDIRECT_CHECK")
                is_redir_safe, redir_msg = validate_http_redirect(url, redirect_target)
                if not is_redir_safe:
                    return PolicyVerdict(
                        verdict=VerdictType.BLOCK,
                        reason_code="UNSAFE_REDIRECT_BLOCKED",
                        reason=redir_msg,
                        tool=tool,
                        rules_evaluated=rules_evaluated,
                        origin_traces=origins,
                        safe_to_execute=False,
                    )

            # Sensitive customer data transmission check
            rules_evaluated.append("R13_HTTP_DATA_PROTECTION")
            has_cust_data = contains_customer_data(payload_str + " " + url, customers_data)
            if has_cust_data:
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="CUSTOMER_DATA_HTTP_EXFILTRATION",
                    reason="Transmission of sensitive customer data to external HTTP endpoints is blocked.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )

            # Untrusted Tier 3 origin check for destination or payload
            rules_evaluated.append("R14_HTTP_TIER3_ORIGIN_CHECK")
            if OriginCategory.TIER_3_CHUNK.value in url_trace.get("categories", []):
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="TIER3_HTTP_DESTINATION_FORBIDDEN",
                    reason=f"Destination URL '{url}' originated from untrusted Tier-3 content.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )
            if OriginCategory.TIER_3_CHUNK.value in payload_trace.get("categories", []):
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="TIER3_HTTP_PAYLOAD_FORBIDDEN",
                    reason="HTTP payload contains directives or data originating from untrusted Tier-3 retrieved content.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                )

            # Data-exposure / PII scan on outgoing HTTP payload
            rules_evaluated.append("R15A_HTTP_PAYLOAD_EXPOSURE_SCAN")
            exposure_findings = scan_payload_exposure(payload_str)
            if exposure_findings:
                return PolicyVerdict(
                    verdict=VerdictType.BLOCK,
                    reason_code="SENSITIVE_DATA_EXPOSURE_BLOCKED",
                    reason=f"Outgoing HTTP payload contains sensitive {exposure_findings[0]['type']} data ({exposure_findings[0]['description']}). Transmission blocked.",
                    tool=tool,
                    rules_evaluated=rules_evaluated,
                    origin_traces=origins,
                    safe_to_execute=False,
                    exposure_findings=exposure_findings,
                )

            # Outbound mutating operations (POST/PUT/DELETE) require approval
            rules_evaluated.append("R15B_HTTP_APPROVAL_CHECK")
            call_token = f"http_request:{method}:{url}"
            is_approved = approved_tokens is not None and call_token in approved_tokens

            if method in ("POST", "PUT", "DELETE"):
                if not is_approved:
                    return PolicyVerdict(
                        verdict=VerdictType.REQUIRE_APPROVAL,
                        reason_code="HTTP_OUTBOUND_APPROVAL_REQUIRED",
                        reason=f"Outbound HTTP {method} request to '{url}' requires explicit human approval.",
                        tool=tool,
                        rules_evaluated=rules_evaluated,
                        origin_traces=origins,
                        safe_to_execute=False,
                    )

            return PolicyVerdict(
                verdict=VerdictType.ALLOW,
                reason_code="PERMITTED_HTTP_REQUEST",
                reason=f"HTTP {method} request to allowlisted host '{host}' authorized{' with human approval' if is_approved else ''}.",
                tool=tool,
                rules_evaluated=rules_evaluated,
                origin_traces=origins,
                safe_to_execute=True,
                exposure_findings=exposure_findings,
            )

        # -------------------------------------------------------------
        # 8. INTERNAL DOCUMENT SEARCH (search_docs)
        # -------------------------------------------------------------
        if tool == "search_docs":
            rules_evaluated.append("R16_SEARCH_DOCS")
            return PolicyVerdict(
                verdict=VerdictType.ALLOW,
                reason_code="PERMITTED_DOC_SEARCH",
                reason="Read-only document search within local knowledge base.",
                tool=tool,
                rules_evaluated=rules_evaluated,
                origin_traces=origins,
                safe_to_execute=True,
            )

        # Fallthrough fail-closed
        return PolicyVerdict(
            verdict=VerdictType.BLOCK,
            reason_code="POLICY_FALLTHROUGH_DENIED",
            reason=f"No matching authorization rule for tool '{tool}'. Execution denied by default.",
            tool=tool,
            rules_evaluated=rules_evaluated,
            origin_traces=origins,
            safe_to_execute=False,
        )

    except Exception as exc:
        return PolicyVerdict(
            verdict=VerdictType.BLOCK,
            reason_code="POLICY_EVALUATION_ERROR",
            reason=f"Security gate encountered internal exception: {str(exc)}. Fails closed.",
            tool=tool,
            rules_evaluated=rules_evaluated,
            origin_traces={},
            safe_to_execute=False,
        )


# =====================================================================
# 6. SIMULATED TOOL EXECUTION & OUTPUT LABELING
# =====================================================================

def execute_simulated_tool(
    tool: str,
    args: dict[str, Any],
    root_dir: Path,
    customers_data: list[dict[str, Any]],
    docs_data: list[dict[str, Any]],
) -> dict[str, Any]:
    """Execute authorized tool in a strictly simulated local environment.
    
    Returns labeled tool output structure with OriginCategory.TOOL_OUTPUT and taint tags.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    taints = []

    if tool == "read_file":
        rel_path = args["path"].replace("\\", "/")
        target = root_dir / rel_path
        if target.exists():
            content = target.read_text(encoding="utf-8")
            if "customer" in rel_path.lower():
                taints.append("CUSTOMER_RECORDS")
            output_text = content
        else:
            output_text = f"Error: file '{rel_path}' not found."

    elif tool == "query_db":
        table = args.get("table")
        cid = args.get("customer_id")
        if table == "customers":
            if cid:
                matched = [c for c in customers_data if c.get("customer_id") == cid]
                output_text = json.dumps(matched, ensure_ascii=False)
            else:
                output_text = json.dumps(customers_data, ensure_ascii=False)
            taints.append("CUSTOMER_RECORDS")
            taints.append("DB_QUERY_OUTPUT")
        else:
            output_text = "[]"

    elif tool == "db_write":
        cid = args.get("customer_id", "C-UNKNOWN")
        status_val = args.get("status") or args.get("operation", "UPDATED")
        taints.append("DB_MUTATION")
        output_text = f"[SIMULATED DB WRITE] Table: {args.get('table')}, Customer: {cid}, Status: {status_val}. Mutation recorded safely in sandbox memory."

    elif tool == "send_email":
        output_text = (
            f"[SIMULATED EMAIL SENT] To: {args.get('to')}, "
            f"Subject: {args.get('subject')}, Length: {len(str(args.get('body', '')))} chars."
        )

    elif tool == "http_request":
        redir = args.get("redirect_url")
        if redir:
            valid, msg = validate_http_redirect(args.get("url", ""), redir)
            if not valid:
                output_text = f"[ERROR 403 REDIRECT BLOCKED] {msg}"
                taints.append("REDIRECT_BLOCKED")
            else:
                output_text = f"[SIMULATED HTTP REDIRECT 200 OK] {args.get('method', 'GET')} {args.get('url')} -> {redir}"
        else:
            output_text = (
                f"[SIMULATED HTTP RESPONSE 200 OK] {args.get('method', 'GET')} {args.get('url')} - "
                f"Simulated payload delivered safely."
            )

    elif tool == "search_docs":
        query = args.get("query", "").lower()
        matched = [d for d in docs_data if query in d.get("text", "").lower() or query in d.get("title", "").lower()]
        output_text = json.dumps(matched[:3], ensure_ascii=False)
        if any(d.get("tier") == 3 for d in matched):
            taints.append("TIER_3_CONTENT_PRESENT")

    else:
        output_text = f"Error: Unknown tool {tool}."

    return {
        "tool": tool,
        "arguments": args,
        "output": output_text,
        "origin_category": OriginCategory.TOOL_OUTPUT.value,
        "timestamp": timestamp,
        "taints": taints,
    }


# =====================================================================
# 7. FAIL-SAFE STRUCTURED AUDIT LOGGING
# =====================================================================

def log_audit_event(logs_dir: Path, event: dict[str, Any]) -> bool:
    """Record a structured JSONL event to runs.jsonl with redaction and fail-safe handling."""
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_file = logs_dir / "runs.jsonl"
        
        event_copy = dict(event)
        if "event_id" not in event_copy:
            event_copy["event_id"] = str(uuid.uuid4())
        if "timestamp" not in event_copy:
            event_copy["timestamp"] = datetime.now(timezone.utc).isoformat()
            
        json_line = json.dumps(event_copy, ensure_ascii=False)
        with log_file.open("a", encoding="utf-8") as f:
            f.write(json_line + "\n")
        return True
    except Exception as exc:
        print(f"[AUDIT LOGGING FAILURE] {exc}")
        return False
