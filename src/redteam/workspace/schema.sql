-- The simulated workspace of one user: mailbox, shared drive, contacts, calendar, a small web,
-- and the sinks an attacker could reach (outbound mail, fetched URLs). Every tool call is audited.

CREATE TABLE IF NOT EXISTS sim_context (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
    id        TEXT PRIMARY KEY,          -- c_0001
    name      TEXT NOT NULL,
    email     TEXT NOT NULL UNIQUE,
    org       TEXT NOT NULL,
    role      TEXT NOT NULL,
    internal  INTEGER NOT NULL DEFAULT 0, -- same company as the user
    note      TEXT NOT NULL DEFAULT ''    -- CRM-style note: untrusted (written by whoever edited it)
);

CREATE TABLE IF NOT EXISTS threads (
    id       TEXT PRIMARY KEY,           -- t_0001
    subject  TEXT NOT NULL,
    topic    TEXT NOT NULL,              -- invoice | meeting | status | vendor | hr | newsletter | support | misc
    label    TEXT NOT NULL DEFAULT 'inbox'
);

CREATE TABLE IF NOT EXISTS messages (
    id          TEXT PRIMARY KEY,        -- m_000001
    thread_id   TEXT NOT NULL REFERENCES threads(id),
    direction   TEXT NOT NULL,           -- in | out
    from_name   TEXT NOT NULL,           -- display name: untrusted
    from_email  TEXT NOT NULL,
    to_emails   TEXT NOT NULL,           -- comma separated
    cc_emails   TEXT NOT NULL DEFAULT '',
    subject     TEXT NOT NULL,           -- untrusted
    body        TEXT NOT NULL,           -- untrusted
    attachments TEXT NOT NULL DEFAULT '[]', -- JSON [{name, mime, text}]: untrusted
    sent_at     TEXT NOT NULL,
    task_id     TEXT NOT NULL DEFAULT '' -- set on messages the agent sent
);

CREATE TABLE IF NOT EXISTS files (
    id           TEXT PRIMARY KEY,       -- f_0001
    path         TEXT NOT NULL UNIQUE,   -- /Finance/Invoices/INV-2026-0412.pdf
    mime         TEXT NOT NULL,
    text         TEXT NOT NULL,          -- extracted text: untrusted
    owner_email  TEXT NOT NULL,
    confidential INTEGER NOT NULL DEFAULT 0,
    modified_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS web_pages (
    url    TEXT PRIMARY KEY,
    title  TEXT NOT NULL,
    text   TEXT NOT NULL                 -- page text (may contain HTML comments etc.): untrusted
);

CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,        -- e_0001
    title       TEXT NOT NULL,
    start_at    TEXT NOT NULL,
    end_at      TEXT NOT NULL,
    attendees   TEXT NOT NULL,           -- comma separated emails
    description TEXT NOT NULL DEFAULT '', -- untrusted when it came from an invite
    task_id     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS fetch_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    url     TEXT NOT NULL,
    found   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS canaries (
    id       TEXT PRIMARY KEY,           -- cn_api_key, cn_salary, cn_roadmap, cn_client_pii ...
    kind     TEXT NOT NULL,              -- secret | pii | confidential
    value    TEXT NOT NULL,              -- the planted string
    location TEXT NOT NULL               -- where it lives (file path / contact / thread)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id        TEXT NOT NULL,
    tool           TEXT NOT NULL,
    kind           TEXT NOT NULL,        -- read | write | security | error
    params_json    TEXT NOT NULL,
    result_summary TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_id);
CREATE INDEX IF NOT EXISTS idx_messages_task ON messages(task_id);
CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_log(task_id);
