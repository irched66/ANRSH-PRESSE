-- ANRSH MAGAZINE only. Additive migration; does not alter articles, breaking_news or editorial_logs.
CREATE TABLE IF NOT EXISTS editorial_accounts (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','editor','contributor')),
  api_key_hash TEXT NOT NULL UNIQUE,
  active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS editorial_sessions (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES editorial_accounts(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_editorial_sessions_expiry ON editorial_sessions(expires_at);
CREATE TABLE IF NOT EXISTS editorial_rate_limits (
  bucket TEXT PRIMARY KEY,
  window_started INTEGER NOT NULL,
  hits INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_editorial_accounts_active ON editorial_accounts(active, role);
