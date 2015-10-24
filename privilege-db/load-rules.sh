#!/bin/bash

/usr/bin/sqlite3 /opt/dbspace/.rules-db.db3 < /usr/share/privilege-control/db/remove-volatile-rules.sql
/usr/bin/shared_cleanup

if [ ! -e /opt/dbspace/.rules_file ]
then
    /usr/bin/sqlite3 /opt/dbspace/.rules-db.db3 < /usr/share/privilege-control/db/load-rules-db.sql > /opt/dbspace/.rules_file
fi

/bin/cat /opt/dbspace/.rules_file | /usr/bin/smack_rules_buffer > /smack/change-rule
