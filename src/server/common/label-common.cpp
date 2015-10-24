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
 * @file        label-common.cpp
 * @author      Zofia Abramowska <z.abramowska@samsung.com>
 * @author      Marcin Karpiuk <m.karpiuk2@samsung.com>
 * @version     1.0
 * @brief       Implementation of common functions for label client and service.
 */

#include <label-common.h>

#include <cstring>
#include <errno.h>
#include <memory>
#include <string>
#include <sys/smack.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <dpl/log/log.h>
#include <security-server-error.h>

namespace SecurityServer {

int labelAccess(const std::string &path, const std::string &label)
{

    int ec = smack_lsetlabel(path.c_str(), label.c_str(), SMACK_LABEL_ACCESS);
    if (ec != 0) {
        return SECURITY_SERVER_API_ERROR_SETTING_ACCESS_LABEL_FAILED;
    }
    return SECURITY_SERVER_API_SUCCESS;
}

int labelTransmute(const std::string &path, int transmute_flag)
{
    // check if path is a directory
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) {
        int error = errno;
        LogError("lstat() failed on " << path << " with error " << strerror(error));
        return SECURITY_SERVER_API_ERROR_SETTING_TRANSMUTE_FLAG_FAILED;
    }

    if (!S_ISDIR(st.st_mode)) {
        return SECURITY_SERVER_API_ERROR_SETTING_TRANSMUTE_FLAG_FAILED;
    }

    int ec = smack_lsetlabel(path.c_str(), transmute_flag ? "1" : "0", SMACK_LABEL_TRANSMUTE);
    if (ec != 0) {
        return SECURITY_SERVER_API_ERROR_SETTING_TRANSMUTE_FLAG_FAILED;
    }
    return SECURITY_SERVER_API_SUCCESS;
}

int smackRuntimeCheck(void)
{
    static int smack_present = -1;
    if (-1 == smack_present) {
        if (smack_smackfs_path()) {
            LogDebug("Smack is enabled");
            smack_present = 1;
        } else {
            LogDebug("Smack is disabled");
            smack_present = 0;
        }
    }
    return smack_present;
}

} /* namespace SecurityServer */
