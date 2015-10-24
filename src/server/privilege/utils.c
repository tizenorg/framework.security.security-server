/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/**
 * @file        utils.c
 * @author      Aleksander Zdyb <a.zdyb@samsung.com>
 * @version     1.0
 * @brief       Utils
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "utils.h"

int copy_file(const char *source, const char *destination) {
    int ret = -1;
    int src_fd = TEMP_FAILURE_RETRY(open(source, O_RDONLY));
    if (src_fd == -1)
        return -1;

    int dest_fd = TEMP_FAILURE_RETRY(creat(destination, S_IRUSR | S_IWUSR));
    if (dest_fd == -1)
        goto close_first;

    struct stat stat_buf;
    ret = fstat(src_fd, &stat_buf);
    if (ret == -1) {
        unlink(destination);
        goto close_both;
    }

    ret = sendfile(dest_fd, src_fd, NULL, stat_buf.st_size);
    if (ret == -1) {
        unlink(destination);
        goto close_both;
    }

close_both:
    close(dest_fd);
close_first:
    close(src_fd);
    return ret;
}

int files_identical(const char *file1, const char *file2) {
    int fd1 = TEMP_FAILURE_RETRY(open(file1, O_RDONLY));
    if (fd1 < 0)
        return 0;

    int fd2 = TEMP_FAILURE_RETRY(open(file2, O_RDONLY));
    if (fd2 < 0)
       goto close_first;

    struct stat stat1;
    if (fstat(fd1, &stat1) != 0)
        goto close_both;

    struct stat stat2;
    if (fstat(fd2, &stat2) != 0)
        goto close_both;

    if (stat1.st_size != stat2.st_size)
        goto close_both;

    char buff1[BUFSIZ];
    char buff2[BUFSIZ];

    int identical = 0;

    while (1) {
        ssize_t buff_read_1 = 0;
        ssize_t buff_read_2 = 0;
        int end_1 = 0;
        int end_2 = 0;

        do {
            ssize_t read_size = TEMP_FAILURE_RETRY(read(fd1, buff1 + buff_read_1, BUFSIZ - buff_read_1));
            if (read_size < 0) {
                goto close_both;
            }
            if (read_size == 0) {
                end_1 = 1;
                break;
            }

            buff_read_1 += read_size;
        } while (buff_read_1 < BUFSIZ);

        do {
            ssize_t read_size = TEMP_FAILURE_RETRY(read(fd2, buff2 + buff_read_2, BUFSIZ - buff_read_2));
            if (read_size < 0) {
                goto close_both;
            }
            if (read_size == 0) {
                end_2 = 1;
                break;
            }

            buff_read_2 += read_size;
        } while (buff_read_2 < BUFSIZ);

        if (buff_read_1 != buff_read_2 || memcmp(buff1, buff2, buff_read_1) != 0)
            break;

        if (end_1 == 1 && end_2 == 1) {
            identical = 1;
            break;
        }
    }

    if (identical) {
        close(fd2);
        close(fd1);
        return 1;
    }

close_both:
    close(fd2);
close_first:
    close(fd1);
    return 0;
}
