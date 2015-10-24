.output /dev/null
-- PRAGMA journal_mode = PERSIST;

BEGIN TRANSACTION;

-- Delete volatile rules
DELETE FROM app_permission WHERE is_volatile = 1;

COMMIT TRANSACTION;
