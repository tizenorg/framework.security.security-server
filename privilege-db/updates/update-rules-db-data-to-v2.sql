--PRAGMA journal_mode = PERSIST;

BEGIN EXCLUSIVE TRANSACTION;

INSERT OR IGNORE INTO app_path_type(name) VALUES("NPRUNTIME_PATH");

COMMIT TRANSACTION;
