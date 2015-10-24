/*
 *  security-server
 *
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <sys/types.h>

#ifndef _SMACK_CHECK_H_
#define _SMACK_CHECK_H_

namespace SecurityServer {

/*
 * A very simple runtime check for SMACK on the platform
 * Returns 1 if SMACK is present, 0 otherwise
 */
int smack_runtime_check(void);

/*
 * A very simple runtime check for SMACK on the platform
 * Returns 1 if SMACK is present, 0 otherwise. If SMACK_ENABLED is not defined
 * It returns 0.
 */
int smack_check(void);

/*
 * Gets smack label of a process in zone, based on its pid.
 *
 * @param  zone         zone name
 * @param  pid          pid of process
 * @param  smack_label  label of process
 * Returns 0 on success, -1 otherwise.
 */
int get_smack_label_from_zone_process(const char *zone, const pid_t pid, char *smack_label);

/*
 * Checks if process with pid in Zone has access to object.
 * This function checks if subject has access to object via smack_have_access() function.
 * If YES then returns access granted. In NO then function checks if process with pid has
 * CAP_MAC_OVERRIDE capability. If YES then returns access granted.
 * If NO then returns access denied.
 *
 * @param  zone         zone name
 * @param  pid          pid of process in zone
 * @param  object       label of object to access
 * @param  access_type  smack access type.
 * @return              0 (no access) or 1 (access) or -1 (error)
 */
int smack_pid_have_access_from_zone(const char *zone, pid_t pid, const char *object,
                                    const char *access_type);

} // namespace SecurityServer

#endif // _SMACK_CHECK_H_
