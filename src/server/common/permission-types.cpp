/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        permission-types.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Implementation of common permissions functions
 */

#include <security-server-error.h>
#include <privilege-control.h>

namespace SecurityServer {

int privilegeToSecurityServerError(int error) {
    switch (error) {
    case PC_OPERATION_SUCCESS:     return SECURITY_SERVER_API_SUCCESS;
    case PC_ERR_MEM_OPERATION:     return SECURITY_SERVER_API_ERROR_OUT_OF_MEMORY;
    case PC_ERR_NOT_PERMITTED:     return SECURITY_SERVER_API_ERROR_ACCESS_DENIED;
    case PC_ERR_INVALID_PARAM:     return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
//TODO validate if adding / changing returned error codes does not break something.
//    All below codes were translated into SECURITY_SERVER_API_ERROR_UNKNOWN,
//    but that code was impossible to reinterprete. That is why I changed it.
    case PC_ERR_FILE_OPERATION:    return SECURITY_SERVER_API_ERROR_FILE_OPEN_FAILED;
    case PC_ERR_INVALID_OPERATION: return SECURITY_SERVER_API_ERROR_OPERATION_NOT_PERMITTED;
    case PC_ERR_DB_OPERATION:      return SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_OPERATION;
    case PC_ERR_DB_LABEL_TAKEN:    return SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_LABEL_TAKEN;
    case PC_ERR_DB_QUERY_PREP:     return SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_QUERY_PREP;
    case PC_ERR_DB_QUERY_BIND:     return SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_QUERY_BIND;
    case PC_ERR_DB_QUERY_STEP:     return SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_QUERY_STEP;
    case PC_ERR_DB_CONNECTION:     return SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_CONNECTION;
    case PC_ERR_DB_NO_SUCH_APP:    return SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_NO_SUCH_APP;
    case PC_ERR_DB_PERM_FORBIDDEN: return SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_PERM_FORBIDDEN;
    default:
        ;
    }
    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}

} //namespace SecurityServer

