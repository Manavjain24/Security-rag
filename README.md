# AgentGuard — Runtime Security for RAG Agents

A local hackathon prototype providing a unified, shared runtime security gate for RAG agents covering:
1. **Email Operations** (`send_email`)
2. **Database Operations** (`query_db`, `db_write`)
3. **Outgoing HTTP Requests** (`http_request`)

Core Security Invariant:
> **Retrieved content is data, not authority. Tool execution is governed by deterministic policies rather than trusting the LLM's judgment.**

---

## 🛠️ Windows PowerShell Setup & Quickstart

1. Open PowerShell in this folder:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. Run the automated test suite (including all 10 focused acceptance tests):
   ```powershell
   pytest -v
   ```

3. Launch the Streamlit application:
   ```powershell
   streamlit run app.py
   ```

---

## 🛡️ Demonstrating the Shared Security Gate

The Streamlit interface provides deterministic guided scenarios covering all 3 tool categories:

1. **Email Security: Poisoned Document Exfiltration (`BLOCK`)**:
   - An external email (`email-099`) instructs the agent to email customer records to `security-review@attacker.test`.
   - **Gate Decision**: `BLOCK` (`TIER3_RECIPIENT_FORBIDDEN`). The recipient is traced to Tier-3 retrieved text. The dispatcher is never invoked.

2. **Database Security: Write Protection (`BLOCK` / `REQUIRE_APPROVAL`)**:
   - A tool attempts to update customer records (`db_write`).
   - If influenced by untrusted Tier-3 content: `BLOCK` (`TIER3_DB_WRITE_FORBIDDEN`).
   - If benign user request without approval: `REQUIRE_APPROVAL` (`DB_WRITE_APPROVAL_REQUIRED`). Can be approved and executed in the UI.

3. **HTTP Security: Data Exfiltration & SSRF Defense (`BLOCK`)**:
   - Outbound HTTP POST to external server with customer data: `BLOCK` (`CUSTOMER_DATA_HTTP_EXFILTRATION` / `UNAUTHORIZED_HTTP_HOST`).
   - Outbound requests to `localhost` or private IP ranges (`127.0.0.1`, `10.x`, `169.254.x` metadata): `BLOCK` (`SSRF_DESTINATION_BLOCKED`).
   - Unsafe redirects to private/internal networks: `BLOCK` (`UNSAFE_REDIRECT_BLOCKED`).
   - Read-only GET requests to allowlisted hosts (`status.example.test`): `ALLOW` (`PERMITTED_HTTP_REQUEST`).

4. **External Report Request (`REQUIRE_APPROVAL`)**:
   - Outbound email to an external auditor domain: `REQUIRE_APPROVAL` (`EMAIL_EXTERNAL_APPROVAL_REQUIRED`). User clicks "Approve and Authorize Tool Call" to execute.

5. **Benign Incident Summary (`ALLOW`)**:
   - Read-only query summarizing internal ticket (`ticket-014`): `ALLOW` (`BENIGN_QUERY`).

---

## 📁 Repository Structure

- `policy.py`: Shared deterministic runtime security gate covering Email, Database, and HTTP, with SSRF protection, redirect verification, canonical SHA-256 hashing, exact entity origin tracing, and audit logging.
- `app.py`: Streamlit interface with multi-category scenario selectors, approval workflow, and execution tracing.
- `tests/test_security_gate.py`: Pytest suite covering all 10 focused acceptance tests and regression coverage.
- `data/documents.json`: Seeded documents across Tier 1 (wiki), Tier 2 (tickets), and Tier 3 (external emails).
- `data/customers.json`: Mock customer data (strictly fictional).
- `logs/runs.jsonl`: Structured JSONL audit log of all security decisions.
- `.streamlit/config.toml`: Streamlit server and theme configuration.
