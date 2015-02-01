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

#include <cookie-common.h>
#include <stdio.h>
#include <unistd.h>
#include <dpl/log/log.h>

namespace SecurityServer {

int getPidPath(char *path, unsigned int pathSize, int pid)
{
    int retval;
    char link[pathSize];

    snprintf(link, pathSize, "/proc/%d/exe", pid);
    retval = readlink(link, path, pathSize-1);
    if (retval < 0) {
        LogDebug("Unable to get process path");
        return -1;
    }
    path[retval] = '\0';

    return 0;
}

} // namespace SecurityServer
