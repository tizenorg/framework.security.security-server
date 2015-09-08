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

#include <stdlib.h>
#include <sys/smack.h>

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

} // namespace SecurityServer
