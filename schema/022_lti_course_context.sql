-- SPDX-License-Identifier: AGPL-3.0-only
-- Optional provider-signed numeric course context; never canonical identity.
BEGIN;
CREATE OR REPLACE FUNCTION canvas_connector.lti_claims_match(payload jsonb, registration canvas_connector.lti_registrations,
 host canvas_connector.platforms, challenge text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE issued bigint; expires bigint; starts bigint; now_seconds bigint; expected_issuer text;
BEGIN
 IF jsonb_typeof(payload) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 IF payload ? 'canvasUserId' AND (jsonb_typeof(payload->'canvasUserId') IS DISTINCT FROM 'string'
   OR NOT canvas_connector.lti_canvas_user_id(payload->>'canvasUserId')) THEN RETURN false; END IF;
 IF payload ? 'canvasCourseId' AND (jsonb_typeof(payload->'canvasCourseId') IS DISTINCT FROM 'string'
   OR NOT canvas_connector.lti_canvas_user_id(payload->>'canvasCourseId')) THEN RETURN false; END IF;
 IF ARRAY(SELECT key FROM jsonb_object_keys(payload-ARRAY['canvasUserId','canvasCourseId']) key ORDER BY key COLLATE "C") IS DISTINCT FROM
  ARRAY['clientId','contextId','deploymentId','expiresAt','issuedAt','issuer','messageType','nonce','notBefore','resourceLinkId','subject','targetLinkUri','version'] THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['issuer','clientId','deploymentId','targetLinkUri','nonce','messageType','version']) name
  WHERE jsonb_typeof(payload->name) IS DISTINCT FROM 'string') THEN RETURN false; END IF;
 expected_issuer:=CASE WHEN registration.trust_profile='self_managed_same_origin' THEN host.canvas_origin
  WHEN registration.environment='production' THEN 'https://canvas.instructure.com'
  WHEN registration.environment='beta' THEN 'https://canvas.beta.instructure.com'
  WHEN registration.environment='test' THEN 'https://canvas.test.instructure.com' END;
 IF NOT COALESCE(payload->>'issuer'=expected_issuer AND payload->>'clientId'=registration.client_id
  AND payload->>'deploymentId'=registration.deployment_id AND payload->>'targetLinkUri'=registration.target_link_uri
  AND payload->>'nonce'=challenge AND payload->>'messageType'='LtiResourceLinkRequest' AND payload->>'version'='1.3.0'
  AND canvas_connector.lti_visible_identifier(payload->>'subject') AND jsonb_typeof(payload->'subject')='string'
  AND canvas_connector.lti_visible_identifier(payload->>'resourceLinkId') AND jsonb_typeof(payload->'resourceLinkId')='string'
  AND (payload->'contextId'='null'::jsonb OR (jsonb_typeof(payload->'contextId')='string'
   AND canvas_connector.lti_visible_identifier(payload->>'contextId'))),false) THEN RETURN false; END IF;
 issued:=canvas_connector.lti_numeric_date(payload->'issuedAt');expires:=canvas_connector.lti_numeric_date(payload->'expiresAt');
 starts:=canvas_connector.lti_numeric_date(payload->'notBefore');now_seconds:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 RETURN COALESCE(issued IS NOT NULL AND expires IS NOT NULL AND expires>now_seconds AND issued<expires
  AND issued<=now_seconds+30 AND now_seconds-issued<=300
  AND (payload->'notBefore'='null'::jsonb OR (starts IS NOT NULL AND starts<=now_seconds)),false);
END;
$$;
COMMIT;
