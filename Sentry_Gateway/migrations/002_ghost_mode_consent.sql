-- Migration 002: Ghost mode opt-in consent flag
--
-- Why this migration exists:
-- Ghost mode (shadow sandbox routing) intercepts an agent's calls and returns
-- plausible fake responses without the agent's knowledge. Activating this on
-- an agent whose developer has not consented raises legal and ethical concerns:
-- it could trigger unintended side effects in the developer's system (e.g. their
-- agent logs a "successful" API call that never happened), and in jurisdictions
-- with strict data processing laws (GDPR Art. 5, UK GDPR) covert interception
-- of an agent's outbound calls may require explicit consent.
--
-- This migration adds ghost_mode_allowed to the agents table. Aegis-0 can only
-- activate ghost mode for agents where this flag is true. Operators must obtain
-- developer consent before enabling ghost mode — the Developer Portal exposes
-- this as an opt-in setting during agent registration (Step 5).
--
-- The flag defaults to FALSE — existing agents are unaffected and ghost mode
-- requires explicit action to enable, not explicit action to disable.

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS ghost_mode_allowed BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN agents.ghost_mode_allowed IS
    'Developer has consented to ghost mode (shadow sandbox) interception for this agent. '
    'Must be TRUE before Aegis-0 can activate ghost mode. Defaults FALSE — opt-in only.';
