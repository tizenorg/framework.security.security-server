/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/*
 * @file        protocols.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file contains list of all protocols suported by security-sever.
 */

#ifndef _SECURITY_SERVER_PROTOCOLS_
#define _SECURITY_SERVER_PROTOCOLS_

#include <cstddef>
#include <time.h>
#include <sys/types.h>

namespace SecurityServer {

extern const size_t SHARED_FILE_QUOTA;
extern const size_t SHARED_FILE_MAX_NUM;

extern char const * const SERVICE_SOCKET_SHARED_MEMORY;
extern char const * const SERVICE_SOCKET_GET_GID;
extern char const * const SERVICE_SOCKET_PRIVILEGE_BY_PID;
extern char const * const SERVICE_SOCKET_PERMISSIONS;
extern char const * const SERVICE_SOCKET_APP_PERMISSIONS;
extern char const * const SERVICE_SOCKET_APP_PRIVILEGE_BY_NAME;
extern char const * const SERVICE_SOCKET_COOKIE_GET;
extern char const * const SERVICE_SOCKET_COOKIE_CHECK;
extern char const * const SERVICE_SOCKET_OPEN_FOR_UNPRIVILEGED;
extern char const * const SERVICE_SOCKET_OPEN_FOR_PRIVILEGED;
extern char const * const SERVICE_SOCKET_PASSWD_CHECK;
extern char const * const SERVICE_SOCKET_PASSWD_SET;
extern char const * const SERVICE_SOCKET_PASSWD_RESET;
extern char const * const SERVICE_SOCKET_LABEL;

enum class AppPermissionsAction {
    BEGIN_RW,
    BEGIN_RO,
    COMMIT,
    ROLLBACK,
    ENABLE,
    DISABLE,
    CHECK_GIVEN_APP,
    CHECK_CALLER_APP,
    INSTALL,
    UNINSTALL,
    PERM_ENABLE,
    PERM_DISABLE,
    REVOKE,
    RESET,
    HAS_PERMISSION,
    GET_PERMISSION,
    GET_APPS_WITH_PERMISSION,
    GET_APP_PERMISSION,
    SETUP_PATH,
    GET_PATH,
    REMOVE_PATH,
    ADD_FRIEND,
    DEFINE_PERMISSION,
    ADDITIONAL_RULES,
    SET_PRIV_VERSION,
    GET_PRIV_VERSION,
    ENABLE_BLACKLIST,
    DISABLE_BLACKLIST,
    GET_BLACKLIST,
    APPLY_SHARING,
    DROP_SHARING
};

enum class LabelCall
{
    SET_ACCESS_LABEL,
    SET_TRANSMUTE_FLAG
};

enum class CookieCall
{
    GET_COOKIE,
    CHECK_PID,
    CHECK_SMACKLABEL,
    CHECK_PRIVILEGE_GID,
    CHECK_PRIVILEGE,
    CHECK_GID,
    CHECK_UID,
    CHECK_ZONE
};

enum class OpenForHdrs : unsigned int
{
    OPEN,
    REOPEN,
    DELETE,
    OPEN_DEPRECATED
};

extern const size_t COOKIE_SIZE;

enum class PasswordHdrs
{
    HDR_IS_PWD_VALID,
    HDR_CHK_PWD,
    HDR_SET_PWD,
    HDR_SET_PWD_VALIDITY,
    HDR_SET_PWD_MAX_CHALLENGE,
    HDR_RST_PWD,
    HDR_SET_PWD_HISTORY,
    HDR_IS_PWD_REUSED,
};

extern const size_t MAX_PASSWORD_LEN;
extern const unsigned int MAX_PASSWORD_HISTORY;
extern const unsigned int PASSWORD_INFINITE_EXPIRATION_DAYS;
extern const unsigned int PASSWORD_INFINITE_ATTEMPT_COUNT;
extern const unsigned int PASSWORD_API_NO_EXPIRATION;

extern const int SECURITY_SERVER_MAX_OBJ_NAME;

} // namespace SecuritySever

#endif // _SECURITY_SERVER_PROTOCOLS_
