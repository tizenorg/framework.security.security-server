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

#include <smack-check.h>
#include <zone-check.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/smack.h>
#include <sys/capability.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <dpl/log/log.h>

namespace SecurityServer {

int smack_runtime_check(void)
{
    static int smack_present = -1;
    if (-1 == smack_present) {
        if (NULL == smack_smackfs_path()) {
            LogDebug("no smack found on device");
            smack_present = 0;
        } else {
            LogDebug("found smack on device");
            smack_present = 1;
        }
    }
    return smack_present;
}

int smack_check(void)
{
#ifndef SMACK_ENABLED
    return 0;
#else
    return smack_runtime_check();
#endif
}

int get_smack_label_from_zone_process(const char *zone, const pid_t pid, char *smack_label)
{
    LogDebug("Entering function: get_smack_label_from_zone_process. Params: zone= " <<
              zone << ", pid= " << pid);

    int ret;
    int fd;
    int PATH_MAX_LEN = 92;
    char path[PATH_MAX_LEN+1];

    if(zone == NULL) {
        LogDebug("Invalid zone param.");
        return -1;
    }

    if (pid < 0) {
        LogDebug("invalid param pid.");
        ret = -1;
        goto out;
    }

    if(smack_label == NULL) {
        //LogDebug("No SMACK. Returning empty label");
        ret = -1;
        goto out;
    }

    bzero(smack_label, SMACK_LABEL_LEN + 1);
    if(!smack_check()) { // If no smack just return success with empty label
        LogDebug("Invalid param smack_label (NULL).");
        ret = 0;
        goto out;
    }

    bzero(path, PATH_MAX_LEN + 1);
    if (strcmp(zone, "host") == 0) {
        snprintf(path, PATH_MAX_LEN, "/proc/%d/attr/current", pid);
    } else {
        snprintf(path, PATH_MAX_LEN, "/var/lib/lxc/%s/rootfs/proc/%d/attr/current", zone, pid);
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        LogDebug("Cannot open file " << std::string(path));
        ret = -1;
        goto out;
    }

    ret = read(fd, smack_label, SMACK_LABEL_LEN);
    close(fd);
    if (ret < 0) {
        LogDebug("Cannot read from file " << std::string(path));
        ret = -1;
        goto out;
    }
    LogDebug("smack_label= " << smack_label);

    ret = 0;
out:
    return ret;
}

int smack_pid_have_access_from_zone(const char *zone, pid_t pid, const char* object,
                                    const char *access_type)
{
    int ret;
    char pid_subject_label[SMACK_LABEL_LEN + 1];
    cap_t cap;
    cap_flag_value_t cap_v;

    if (!smack_check()) {
        LogDebug("No SMACK. Return access granted");
        return -1;
    }

    if(zone == NULL) {
        LogDebug("Invalid zone param.");
        return -1;
    }

    if (pid < 0) {
        LogDebug("Invalid pid.");
        return -1;
    }

    if(object == NULL) {
        LogDebug("Invalid object param.");
        return -1;
    }

    if(access_type == NULL) {
        LogDebug("Invalid access_type param");
        return -1;
    }

    //get SMACK label of process
    ret = get_smack_label_from_zone_process(zone, pid, pid_subject_label);
    if (ret != 0) {
        if((strcmp(zone, "host") != 0) && (pid == 0))
            return 1;

        LogDebug("get_smack_label_from_process " << pid << " failed");
        return -1;
    }
    LogDebug("Zone(pid) " << zone << "(" << pid << ") has label: " << pid_subject_label);

    // do not call smack_have_access() if label is empty
    if (pid_subject_label[0] != '\0') {
        ret = smack_have_access(pid_subject_label, object, access_type);
        if ( -1 == ret) {
            LogDebug("smack_have_access failed.");
            return -1;
        }
        if ( 1 == ret ) { // smack_have_access return 1 (access granted)
            LogDebug("smack_have_access returned 1 (access granted)");
            return 1;
        }
    }

    // smack_have_access returned 0 (access denied). Now CAP_MAC_OVERRIDE should be checked
    LogDebug("smack_have_access returned 0 (access denied)");
    if (strcmp(zone, "host") != 0) {
        std::string zoneName(zone);
        ret = zone_pid_has_cap(zoneName, pid, CAP_MAC_OVERRIDE, CAP_EFFECTIVE);
        if (ret == 1) {
            LogDebug("pid " << pid << " has CAP_MAC_OVERRIDE");
            return 1;
        } else if (ret == 0) {
            LogDebug("pid " << pid << " doesn't have CAP_MAC_OVERRIDE");
            return 0;
        } else {
            LogDebug("pid " << pid << "'s capabilities can't be read");
            return 0;
        }
    } else {
        cap = cap_get_pid(pid);
        if (cap == NULL) {
            LogDebug("cap_get_pid failed");
            return -1;
        }
        ret = cap_get_flag(cap, CAP_MAC_OVERRIDE, CAP_EFFECTIVE, &cap_v);
        if (0 != ret) {
            LogDebug("cap_get_flag failed");
            return -1;
        }

        if (cap_v == CAP_SET) {
            LogDebug("pid " << pid << " has CAP_MAC_OVERRIDE");
            return 1;
        } else {
            LogDebug("pid " << pid << " doesn't have CAP_MAC_OVERRIDE");
            return 0;
        }
    }
}
} // namespace SecurityServer
