-- ============================================================
-- CyberScope OSINT Platform — PostgreSQL Schema
-- Run: psql -U postgres -d cyberscope -f schema.sql
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Roles ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS roles (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(30) NOT NULL UNIQUE,  -- Admin, Analyst, Viewer
    permissions JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO roles (name, permissions) VALUES
    ('Admin',   '["*"]'),
    ('Analyst', '["read_all","scan","export","view_siem"]'),
    ('Viewer',  '["read_dashboard","read_threat","read_graph"]')
ON CONFLICT (name) DO NOTHING;

-- ─── Users ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email         VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARCHAR(72)  NOT NULL,           -- bcrypt
    name          VARCHAR(100) NOT NULL,
    role          VARCHAR(30)  NOT NULL DEFAULT 'Analyst' REFERENCES roles(name),
    status        VARCHAR(20)  NOT NULL DEFAULT 'active',  -- active | suspended
    avatar_url    TEXT,
    last_login    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email  ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role   ON users(role);

-- ─── Scan Results ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_results (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        VARCHAR(30) NOT NULL,    -- domain | ip | social | threat | port
    target      VARCHAR(500) NOT NULL,
    result      JSONB NOT NULL DEFAULT '{}',
    risk_score  SMALLINT CHECK (risk_score BETWEEN 0 AND 100),
    risk_label  VARCHAR(20),             -- Safe | Low | Medium | High | Critical
    status      VARCHAR(20) DEFAULT 'done', -- queued | running | done | failed
    shared      BOOLEAN DEFAULT FALSE,
    notes       TEXT,
    tags        VARCHAR(50)[] DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scans_user_id    ON scan_results(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_type       ON scan_results(type);
CREATE INDEX IF NOT EXISTS idx_scans_target     ON scan_results(target);
CREATE INDEX IF NOT EXISTS idx_scans_risk_score ON scan_results(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scan_results(created_at DESC);

-- ─── Risk Scores ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS risk_scores (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id       UUID NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    score         SMALLINT NOT NULL CHECK (score BETWEEN 0 AND 100),
    label         VARCHAR(20) NOT NULL,
    confidence    VARCHAR(10),           -- low | medium | high
    features      JSONB NOT NULL DEFAULT '{}',
    explanation   TEXT[],
    model_version VARCHAR(30) DEFAULT 'weighted-logistic-v1',
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Activity Logs ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS activity_logs (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    action      VARCHAR(100) NOT NULL,   -- LOGIN | DOMAIN_SCAN | IP_SCAN | etc.
    resource    VARCHAR(500),
    metadata    JSONB DEFAULT '{}',
    ip_address  INET,
    user_agent  TEXT,
    level       VARCHAR(20) DEFAULT 'info',  -- info | warn | error | success
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activity_user_id   ON activity_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_action     ON activity_logs(action);
CREATE INDEX IF NOT EXISTS idx_activity_created_at ON activity_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_level      ON activity_logs(level);

-- ─── Audit Logs (Immutable) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email VARCHAR(254),            -- denormalized for immutability
    action      VARCHAR(100) NOT NULL,
    resource    VARCHAR(500),
    before_data JSONB,
    after_data  JSONB,
    ip_address  INET,
    status      VARCHAR(20) DEFAULT 'success',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Audit logs should NOT be deletable (enforce via DB role policy)
CREATE INDEX IF NOT EXISTS idx_audit_actor_id   ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at DESC);

-- ─── Shared Targets (Team Collaboration) ──────────────────────
CREATE TABLE IF NOT EXISTS shared_targets (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target      VARCHAR(500) NOT NULL,
    type        VARCHAR(30) NOT NULL,
    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    notes       TEXT,
    tags        VARCHAR(50)[] DEFAULT '{}',
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Alert Rules (SIEM) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_rules (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(100) NOT NULL,
    condition   TEXT NOT NULL,            -- DSL or JSON condition expression
    severity    VARCHAR(20) DEFAULT 'medium',
    is_active   BOOLEAN DEFAULT TRUE,
    created_by  UUID REFERENCES users(id),
    notified_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Updated_at Trigger ───────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_updated_at ON users;
CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
