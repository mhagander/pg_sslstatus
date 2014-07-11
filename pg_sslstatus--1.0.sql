CREATE FUNCTION pg_get_sslstatus(OUT pid int, OUT ssl bool, OUT bits int, OUT compression bool, OUT version text, OUT cipher text, OUT clientdn text) RETURNS SETOF RECORD
AS 'MODULE_PATHNAME', 'pg_get_sslstatus'
LANGUAGE C IMMUTABLE STRICT;

CREATE VIEW pg_sslstatus AS
SELECT * FROM pg_get_sslstatus();
