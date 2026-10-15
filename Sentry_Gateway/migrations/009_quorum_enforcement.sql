-- ============================================================================
-- Migration 009: Quorum Enforcement Column
-- ============================================================================
--
-- Adds the required_votes column to ciba_authorization_requests so the
-- Gateway can enforce M-of-N multi-approval quorum per hold.
--
-- Default is 1 (single-operator approval). Tenants can configure this
-- per-policy via the Dashboard.
--
-- Safe to re-run: uses IF NOT EXISTS pattern via DO block.
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'ciba_authorization_requests'
        AND column_name = 'required_votes'
    ) THEN
        ALTER TABLE ciba_authorization_requests
            ADD COLUMN required_votes INTEGER NOT NULL DEFAULT 1;
        COMMENT ON COLUMN ciba_authorization_requests.required_votes IS
            'M-of-N quorum requirement. 1 = single approval (default). >1 = multi-operator quorum.';
    END IF;
END
$$;
