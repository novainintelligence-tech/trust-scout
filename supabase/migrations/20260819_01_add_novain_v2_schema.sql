BEGIN;

-- 1) ALTER existing verifications table (additive only; preserve evidence JSONB)
ALTER TABLE public.verifications
  ADD COLUMN IF NOT EXISTS engine_version TEXT NOT NULL DEFAULT '2.0.0',
  ADD COLUMN IF NOT EXISTS target_type TEXT NOT NULL DEFAULT 'website',
  ADD COLUMN IF NOT EXISTS verification_id TEXT,
  ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now();

-- Ensure verification_id is unique (customer-facing id)
CREATE UNIQUE INDEX IF NOT EXISTS verifications_verification_id_uniq ON public.verifications (verification_id);

-- Protective CHECK: enforce trust_score bounds (0..100). If you prefer NOT VALID, tell me.
ALTER TABLE public.verifications
  ADD CONSTRAINT verifications_trust_score_range CHECK (trust_score BETWEEN 0 AND 100);

-- 2) profiles (do NOT create public.users; reference Supabase auth.users)
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  display_name TEXT,
  organisation TEXT,
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS profiles_display_name_idx ON public.profiles (display_name);

-- 3) verification_sources (registry) + seed canonical internal sources
CREATE TABLE IF NOT EXISTS public.verification_sources (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  source_type TEXT NOT NULL,        -- e.g. 'http','tls','rdap','dns','headers','content','identity'
  provider TEXT,
  base_url TEXT,
  status TEXT NOT NULL DEFAULT 'active',      -- active | degraded | disabled
  reliability_score NUMERIC NOT NULL DEFAULT 1.0 CHECK (reliability_score >= 0 AND reliability_score <= 1),
  metadata JSONB DEFAULT '{}'::jsonb,
  last_checked_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS verification_sources_name_idx ON public.verification_sources (name);

-- Seed canonical internal sources (only these; no fake reputation provider)
INSERT INTO public.verification_sources (id, name, source_type, provider, base_url, status, reliability_score)
VALUES
  (gen_random_uuid(), 'http_probe', 'http', 'novain_internal', NULL, 'active', 1.0),
  (gen_random_uuid(), 'tls_probe', 'tls', 'novain_internal', NULL, 'active', 1.0),
  (gen_random_uuid(), 'rdap', 'rdap', 'novain_internal', NULL, 'active', 1.0),
  (gen_random_uuid(), 'dns', 'dns', 'novain_internal', NULL, 'active', 1.0),
  (gen_random_uuid(), 'security_headers', 'headers', 'novain_internal', NULL, 'active', 1.0),
  (gen_random_uuid(), 'page_content', 'content', 'novain_internal', NULL, 'active', 1.0),
  (gen_random_uuid(), 'identity_analysis', 'identity', 'novain_internal', NULL, 'active', 1.0)
ON CONFLICT (name) DO NOTHING;

-- 4) verification_checks
CREATE TABLE IF NOT EXISTS public.verification_checks (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  verification_id UUID NOT NULL REFERENCES public.verifications(id) ON DELETE CASCADE,
  category TEXT NOT NULL,           -- infrastructure, domain, identity, reputation, content, anomaly, etc.
  check_type TEXT NOT NULL,         -- tls, rdap, dns, headers, content_analysis, company_match...
  status TEXT NOT NULL,             -- PASS | FAIL | WARNING | UNAVAILABLE | UNKNOWN
  score NUMERIC NOT NULL DEFAULT 0, -- raw contribution (can be negative)
  confidence NUMERIC NOT NULL DEFAULT 0.0 CHECK (confidence >= 0 AND confidence <= 1),
  weight NUMERIC NOT NULL DEFAULT 1.0,
  source_id UUID REFERENCES public.verification_sources(id),
  severity TEXT,                    -- LOW | MEDIUM | HIGH | CRITICAL
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS verification_checks_verification_idx ON public.verification_checks (verification_id);
CREATE INDEX IF NOT EXISTS verification_checks_source_idx ON public.verification_checks (source_id);

-- 5) verification_evidence
CREATE TABLE IF NOT EXISTS public.verification_evidence (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  verification_id UUID NOT NULL REFERENCES public.verifications(id) ON DELETE CASCADE,
  check_id UUID REFERENCES public.verification_checks(id) ON DELETE CASCADE,
  source_id UUID REFERENCES public.verification_sources(id),
  evidence_type TEXT NOT NULL,      -- cert, redirect, rdap-record, dns-record, header-check, content-snippet
  observation JSONB NOT NULL,
  result TEXT NOT NULL,             -- PASS | FAIL | WARNING | UNAVAILABLE | UNKNOWN
  severity TEXT,                    -- LOW | MEDIUM | HIGH | CRITICAL
  confidence NUMERIC NOT NULL DEFAULT 1.0 CHECK (confidence >= 0 AND confidence <= 1),
  weight NUMERIC NOT NULL DEFAULT 0.0,
  observed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  expires_at TIMESTAMP WITH TIME ZONE,
  raw_reference TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS verification_evidence_check_idx ON public.verification_evidence (check_id);
CREATE INDEX IF NOT EXISTS verification_evidence_verification_idx ON public.verification_evidence (verification_id);
CREATE INDEX IF NOT EXISTS verification_evidence_source_idx ON public.verification_evidence (source_id);

-- 6) verification_score_contributions (audit trail connecting rules/evidence -> numeric contribution)
CREATE TABLE IF NOT EXISTS public.verification_score_contributions (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  verification_id UUID NOT NULL REFERENCES public.verifications(id) ON DELETE CASCADE,
  check_id UUID REFERENCES public.verification_checks(id) ON DELETE CASCADE,
  evidence_id UUID REFERENCES public.verification_evidence(id) ON DELETE CASCADE,
  rule_id UUID REFERENCES public.risk_rules(id),
  contribution NUMERIC NOT NULL,  -- signed numeric contribution (could be negative)
  reason TEXT NOT NULL,           -- human readable reason or rule_code
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS vsc_verification_idx ON public.verification_score_contributions (verification_id);
CREATE INDEX IF NOT EXISTS vsc_evidence_idx ON public.verification_score_contributions (evidence_id);

-- 7) verification_reports (cached final report, sanitized by API)
CREATE TABLE IF NOT EXISTS public.verification_reports (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  verification_id UUID NOT NULL REFERENCES public.verifications(id) ON DELETE CASCADE,
  report JSONB NOT NULL,
  published_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  engine_version TEXT
);

CREATE INDEX IF NOT EXISTS verification_reports_verification_idx ON public.verification_reports (verification_id);

-- 8) api_keys (profile-linked; do NOT store plaintext keys)
CREATE TABLE IF NOT EXISTS public.api_keys (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  key_id TEXT NOT NULL UNIQUE,            -- user-facing prefix/display id
  profile_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
  name TEXT,
  key_hash TEXT NOT NULL,                 -- hash only (app must store using argon2id/bcrypt)
  status TEXT NOT NULL DEFAULT 'active',
  environment TEXT NOT NULL DEFAULT 'production',
  rate_limit INTEGER DEFAULT 1000,
  last_used_at TIMESTAMP WITH TIME ZONE,
  expires_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS api_keys_key_id_idx ON public.api_keys (key_id);

-- 9) api_usage
CREATE TABLE IF NOT EXISTS public.api_usage (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  api_key_id UUID REFERENCES public.api_keys(id),
  profile_id UUID REFERENCES public.profiles(id),
  verification_id UUID REFERENCES public.verifications(id),
  endpoint TEXT NOT NULL,
  request_id TEXT,
  status_code INTEGER,
  units NUMERIC DEFAULT 1,
  unit_price NUMERIC,
  currency TEXT DEFAULT 'USD',
  latency_ms INTEGER,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS api_usage_apikey_created_idx ON public.api_usage (api_key_id, created_at DESC);

-- 10) risk_rules (versioned)
CREATE TABLE IF NOT EXISTS public.risk_rules (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  rule_code TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '1.0.0',
  category TEXT,
  name TEXT,
  description TEXT,
  severity TEXT,
  score_impact NUMERIC NOT NULL,
  confidence NUMERIC DEFAULT 1.0 CHECK (confidence >= 0 AND confidence <= 1),
  enabled BOOLEAN NOT NULL DEFAULT true,
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  UNIQUE (rule_code, version)
);

CREATE INDEX IF NOT EXISTS risk_rules_code_idx ON public.risk_rules (rule_code);

-- 11) risk_gates (versioned)
CREATE TABLE IF NOT EXISTS public.risk_gates (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  gate_code TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '1.0.0',
  name TEXT,
  description TEXT,
  trigger_condition JSONB NOT NULL,
  maximum_score INTEGER,
  minimum_risk_level TEXT,
  severity TEXT,
  enabled BOOLEAN NOT NULL DEFAULT true,
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  UNIQUE (gate_code, version)
);

CREATE INDEX IF NOT EXISTS risk_gates_code_idx ON public.risk_gates (gate_code);

-- 12) agent_clients
CREATE TABLE IF NOT EXISTS public.agent_clients (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  client_type TEXT,
  provider TEXT,
  identifier TEXT UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMP WITH TIME ZONE
);

-- 13) payment_transactions
CREATE TABLE IF NOT EXISTS public.payment_transactions (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  verification_id UUID REFERENCES public.verifications(id),
  api_key_id UUID REFERENCES public.api_keys(id),
  agent_client_id UUID REFERENCES public.agent_clients(id),
  payment_protocol TEXT,
  network TEXT,
  asset TEXT,
  amount NUMERIC,
  currency TEXT,
  payment_reference TEXT,
  status TEXT,
  payer JSONB,
  payee JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  confirmed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS payment_transactions_verification_idx ON public.payment_transactions (verification_id);

-- 14) entity_observations
CREATE TABLE IF NOT EXISTS public.entity_observations (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  verification_id UUID REFERENCES public.verifications(id),
  entity_type TEXT NOT NULL,    -- domain, company, email, phone, ip, certificate, payment_destination
  entity_value TEXT NOT NULL,
  observation JSONB NOT NULL,
  confidence NUMERIC DEFAULT 1.0 CHECK (confidence >= 0 AND confidence <= 1),
  observed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS entity_observations_entity_idx ON public.entity_observations (entity_type, entity_value);

-- 15) RLS and grants: keep existing verifications public policy; DO NOT open the new tables to anon.
-- We intentionally do NOT create GRANT SELECT to anon for the new tables.
-- Preserve service_role permissions by default (Supabase service_role has elevated rights outside migrations).
-- If desired, we can later add RLS policies to expose sanitized reports via an API.

COMMIT;
