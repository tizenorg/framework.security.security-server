--PRAGMA journal_mode = PERSIST;

BEGIN EXCLUSIVE TRANSACTION;

CREATE TABLE IF NOT EXISTS app_shared_path(
    owner_label_name TEXT NOT NULL,
    target_label_name TEXT NOT NULL,
    path TEXT NOT NULL,
    counter INTEGER NOT NULL,
    PRIMARY KEY(owner_label_name, target_label_name, path)
);

--assume, that database is in version V7
PRAGMA user_version = 8;

COMMIT TRANSACTION;
