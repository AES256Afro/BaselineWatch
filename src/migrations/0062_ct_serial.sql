-- One issuance, one key (audit of 2026-11-16). crt.sh lists a precertificate and its certificate
-- under two ids with the same serial from the same issuer; parseCrtsh already folds the pair on
-- (serial, issuer DN), but the stored rows had no serial, so a later read could only tell a known
-- issuance by its issuer, names and start. The serial and the issuer's full DN are kept from now on
-- and issuanceKey in src/ct.ts reads both; a row stored before this has neither and keeps the old key.
ALTER TABLE ct_certs ADD COLUMN serial TEXT;       -- lower-case hex as crt.sh gives it
ALTER TABLE ct_certs ADD COLUMN issuer_dn TEXT;    -- the issuer's distinguished name, as crt.sh gives it
