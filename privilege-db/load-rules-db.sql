.load librules-db-sql-udf.so
.separator " "

.output /dev/null
-- PRAGMA journal_mode = PERSIST;


BEGIN TRANSACTION;

.output stdout
SELECT   subject, object, access_to_str(bitwise_or(access)), "-"
FROM     all_smack_binary_rules
WHERE    is_volatile = 0
GROUP BY subject, object
ORDER BY subject, object ASC;

COMMIT TRANSACTION;
