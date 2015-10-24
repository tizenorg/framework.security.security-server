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

#include <string>
#include <sys/capability.h>

namespace SecurityServer {

/*
 * Declare hardlink to vsm context
 * Returns 0 on success, or negative value on error. If ZONE_ENABLED is not defined
 * It returns 0.
 */

int zone_declare_link(const std::string &hostPath, const std::string &zonePath);

/*
 * Get default zone name.
 */

void zone_get_default_zone(std::string &zoneName);

/*
 * Get path for zone.
 */

void zone_get_path_from_zone(const std::string &path, const std::string &zoneName,
                             std::string &zonePath);

/*
 * Check zone validity by name.
 * Return true on a running zone.
 */

bool zone_check_validity_name(const std::string &zoneName);

/*
 * Find zone name associated with pid or sockfd
 * Returns 0 on success, 1 otherwise. If ZONE_ENABLED is not defined
 * It returns 0.
 */

int lookup_zone_by_pid(int pid, std::string &zoneName);
int lookup_zone_by_sockfd(int sockfd, std::string &zoneName);

/*
 * Read zone's process capabilities and comapre
 * Returns 1 on that process has capabilities, 0 otherwise. -1 on failed
 */

int zone_pid_has_cap(const std::string &zoneName, pid_t pid, cap_value_t cap, cap_flag_t flag);

} // namespace SecurityServer

