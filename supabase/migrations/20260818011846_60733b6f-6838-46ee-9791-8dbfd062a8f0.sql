CREATE TABLE public.verifications (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  target TEXT NOT NULL,
  domain TEXT NOT NULL,
  trust_score INTEGER NOT NULL,
  risk_level TEXT NOT NULL,
  status TEXT NOT NULL,
  confidence NUMERIC NOT NULL,
  capped BOOLEAN NOT NULL DEFAULT false,
  cap_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
  categories JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  recommendation TEXT NOT NULL DEFAULT '',
  duration_ms INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX verifications_domain_idx ON public.verifications (domain, created_at DESC);

GRANT SELECT ON public.verifications TO anon;
GRANT SELECT ON public.verifications TO authenticated;
GRANT ALL ON public.verifications TO service_role;

ALTER TABLE public.verifications ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Verification reports are publicly readable"
  ON public.verifications FOR SELECT
  USING (true);