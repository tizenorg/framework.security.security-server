# Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# @file        CMakeLists.txt
# @author      Lukasz Wojciechowski <l.wojciechow@partner.samsung.com>
# @brief       Recipes for privilege database
#

###################################################################################################
## SQL scripts preprocessing to contain current Tizen OS version
FILE(GLOB_RECURSE SQL_SCRIPTS "*.sql.in")
FOREACH(SQL_SCRIPT ${SQL_SCRIPTS})
        GET_FILENAME_COMPONENT(SQL_SCRIPT_PATH "${SQL_SCRIPT}" PATH)
        GET_FILENAME_COMPONENT(SQL_SCRIPT_WE   "${SQL_SCRIPT}" NAME_WE)
        CONFIGURE_FILE("${SQL_SCRIPT}" "${SQL_SCRIPT_PATH}/${SQL_SCRIPT_WE}.sql" @ONLY)
ENDFOREACH(SQL_SCRIPT)

###################################################################################################
## for rules-db-sql-udf.so (library)
SET(rules-db-sql-udf_SOURCES ${CMAKE_SOURCE_DIR}/privilege-db/rules-db-sql-udf.c)
SET(rules-db-sql-udf_CFLAGS  " ${CFLAGS} -fPIC")

ADD_LIBRARY(rules-db-sql-udf MODULE ${rules-db-sql-udf_SOURCES})
SET_TARGET_PROPERTIES(rules-db-sql-udf PROPERTIES COMPILE_FLAGS "${rules-db-sql-udf_CFLAGS}")
SET_TARGET_PROPERTIES(rules-db-sql-udf PROPERTIES LINK_FLAGS "${rules-db-sql-udf_LDFLAGS}")

###################################################################################################

INSTALL(TARGETS rules-db-sql-udf DESTINATION  ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)

INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/rules-db.sql DESTINATION /usr/share/privilege-control/db)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/rules-db-data.sql DESTINATION /usr/share/privilege-control/db)
INSTALL(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/updates/ DESTINATION /usr/share/privilege-control/db/updates PATTERN "*.sql.in" EXCLUDE)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/updater.sh DESTINATION /usr/share/privilege-control/db
     PERMISSIONS OWNER_READ
                 OWNER_WRITE
                 OWNER_EXECUTE
                 GROUP_READ
                 GROUP_WRITE
                 GROUP_EXECUTE
                 WORLD_READ
                 WORLD_WRITE
                 WORLD_EXECUTE)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/load-rules-db.sql
              ${CMAKE_CURRENT_BINARY_DIR}/remove-volatile-rules.sql
        DESTINATION /usr/share/privilege-control/db)

INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/220.libprivilege-updater.patch.sh DESTINATION /etc/opt/upgrade
     PERMISSIONS OWNER_READ
                 OWNER_WRITE
                 OWNER_EXECUTE)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/load-rules.sh DESTINATION /usr/bin
     PERMISSIONS OWNER_READ
                 OWNER_EXECUTE)