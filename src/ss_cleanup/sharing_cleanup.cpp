/*
 * libprivilege control, rules database
 *
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Jan Olszak <j.olszak@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/**
* @file        sharing_cleanup.c
* @author      Zofia Abramowska (z.abramowska@samsung.com)
* @version     1.0
* @brief       Binary file for loading predefined API features to the database.
*/

#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <unistd.h>

#include <sys/smack.h>
#include <errno.h>

extern "C" {
#include <common.h>
}

#include <privilege-control.h>

namespace {
const std::string tmp_flag = "/tmp/ss-cleanup-tmp-flag";
}

bool create_file(const std::string &path) {
    int fd;
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    fd = TEMP_FAILURE_RETRY(creat(path.c_str(), mode));
    if (fd == -1) {
        std::cerr << "Creating file " << path << " failed with " << strerror(errno);
        return false;
    }
    close(fd);
    return true;
}

int main(void)
{
    if (file_exists(tmp_flag.c_str()))
        return EXIT_SUCCESS;
    int ret = ss_perm_clear_sharing();
    if (ret != PC_OPERATION_SUCCESS) {
        std::cerr << "ss_perm_clear_sharing failed with: " << ss_perm_strerror(ret);
        return EXIT_FAILURE;
    }

    if (!create_file(tmp_flag))
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
