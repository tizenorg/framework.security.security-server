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
 *
 */

#ifndef SECURITY_SERVER_PERM_TYPES_H
#define SECURITY_SERVER_PERM_TYPES_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ss_transaction ss_transaction;

typedef enum {
        PERM_APP_TYPE_FIRST, // It has to be the first one

        PERM_APP_TYPE_WRT = PERM_APP_TYPE_FIRST,
        PERM_APP_TYPE_OSP,
        PERM_APP_TYPE_OTHER,
        PERM_APP_TYPE_WRT_PARTNER,
        PERM_APP_TYPE_WRT_PLATFORM,
        PERM_APP_TYPE_OSP_PARTNER,
        PERM_APP_TYPE_OSP_PLATFORM,
        PERM_APP_TYPE_EFL,
        PERM_APP_TYPE_EFL_PARTNER,
        PERM_APP_TYPE_EFL_PLATFORM,

        PERM_APP_TYPE_LAST = PERM_APP_TYPE_EFL_PLATFORM // It has to be the last one
} app_type_t;

typedef enum {
        PERM_APP_PATH_PRIVATE,
        PERM_APP_PATH_GROUP,
        PERM_APP_PATH_PUBLIC,
        PERM_APP_PATH_SETTINGS,
        PERM_APP_PATH_NPRUNTIME,
        PERM_APP_PATH_ANY_LABEL,
} app_path_type_t;

typedef struct perm_app_status {
        char *app_id;
        bool is_enabled;
        bool is_permanent;
} perm_app_status_t;

typedef struct perm_blacklist_status {
        char *permission_name;
        app_type_t type;
        bool is_enabled;
} perm_blacklist_status_t;

// TODO: after all projects change their code delete these defines
// Historical in app_type_t
#define PERM_APP_TYPE_WGT PERM_APP_TYPE_WRT
#define PERM_APP_TYPE_WGT_PARTNER PERM_APP_TYPE_WRT_PARTNER
#define PERM_APP_TYPE_WGT_PLATFORM PERM_APP_TYPE_WRT_PLATFORM


#define APP_TYPE_WGT PERM_APP_TYPE_WRT
#define APP_TYPE_OSP PERM_APP_TYPE_OSP
#define APP_TYPE_OTHER PERM_APP_TYPE_OTHER
#define APP_TYPE_WGT_PARTNER PERM_APP_TYPE_WRT_PARTNER
#define APP_TYPE_WGT_PLATFORM PERM_APP_TYPE_WRT_PLATFORM
#define APP_TYPE_OSP_PARTNER PERM_APP_TYPE_OSP_PARTNER
#define APP_TYPE_OSP_PLATFORM PERM_APP_TYPE_OSP_PLATFORM
#define APP_TYPE_EFL PERM_APP_TYPE_EFL
#define APP_TYPE_EFL_PARTNER PERM_APP_TYPE_EFL_PARTNER
#define APP_TYPE_EFL_PLATFORM PERM_APP_TYPE_EFL_PLATFORM

// Historical names in app_path_type_t
#define APP_PATH_PRIVATE PERM_APP_PATH_PRIVATE
#define APP_PATH_GROUP PERM_APP_PATH_GROUP
#define APP_PATH_PUBLIC PERM_APP_PATH_PUBLIC
#define APP_PATH_SETTINGS PERM_APP_PATH_SETTINGS
#define APP_PATH_ANY_LABEL PERM_APP_PATH_ANY_LABEL
#define APP_PATH_GROUP_RW APP_PATH_GROUP
#define APP_PATH_PUBLIC_RO APP_PATH_PUBLIC
#define APP_PATH_SETTINGS_RW APP_PATH_SETTINGS

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_SERVER_PERM_TYPES_H */

