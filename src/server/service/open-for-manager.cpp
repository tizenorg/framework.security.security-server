/*
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
/*
 * @file        open-for-manager.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @version     1.0
 * @brief       Implementation of open-for management functions
 */

#include "open-for-manager.h"

#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <attr/xattr.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>

#include <sys/smack.h>
#include <smack-check.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <security-server.h>
#include <security-server-util.h>
#include <error-description.h>

const std::string XATTR_NAME = "security.openfor.provider";
const std::string DATA_DIR = "/var/run/security-server";
const std::string ALLOWED_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ \
                                   abcdefghijklmnopqrstuvwxyz \
                                   0123456789._-";

namespace SecurityServer
{
    // SockCred implementations
    SockCred::SockCred()
    {
        m_len = sizeof(struct ucred);
        memset(&m_cr, 0, m_len);
    }

    bool SockCred::getCred(int socket)
    {
        if (getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &m_cr, &m_len)) {
            int err = errno;
            LogError("Unable to get client credentials: " << errnoToString(err));
            return true;
        }

        if (smack_check()) {
            char label[SMACK_LABEL_LEN + 1];
            if (PC_OPERATION_SUCCESS != get_smack_label_from_process(m_cr.pid, label)) {
                LogError("Unable to get smack label of process.");
                return true;
            }
            m_sockSmackLabel = label;
        } else
            m_sockSmackLabel.clear();

        return false;
    }

    std::string SockCred::getLabel() const
    {
        return m_sockSmackLabel;
    }

    // SharedFile implementations
    SharedFile::SharedFile()
    {
        if (!dirExist(DATA_DIR.c_str()))
            mkdir(DATA_DIR.c_str(), 0700);
        else {
            deleteDir(DATA_DIR.c_str());
            mkdir(DATA_DIR.c_str(), 0700);
        }
    }

    bool SharedFile::fileExist(const std::string &filename)
    {
        std::string filepath = DATA_DIR + "/" + filename;
        struct stat buf;

        return ((lstat(filepath.c_str(), &buf) == 0) &&
                (((buf.st_mode) & S_IFMT) != S_IFLNK));
    }

    bool SharedFile::dirExist(const std::string &dirpath)
    {
        struct stat buf;

        return ((lstat(dirpath.c_str(), &buf) == 0) &&
                (((buf.st_mode) & S_IFMT) == S_IFDIR));
    }

    bool SharedFile::deleteDir(const std::string &dirpath)
    {
        DIR *dirp;
        struct dirent *dentry;
        struct dirent *dp = NULL;
        char path[PATH_MAX];

        if ((dirp = opendir(dirpath.c_str())) == NULL) {
            int err = errno;
            LogError("Cannot open data directory. " << errnoToString(err));
            return true;
        }

        size_t len = offsetof(struct dirent, d_name) + pathconf(dirpath.c_str(), _PC_NAME_MAX) + 1;
        dentry = (struct dirent*)malloc(len);

        if (!dentry) {
            LogError("Cannot open directory. Not enough memory!");
            closedir(dirp);
            return true;
        }

        while ((!readdir_r(dirp, dentry, &dp)) && dp) {
            if (strcmp(dp->d_name, ".") && strcmp(dp->d_name, "..")) {
                snprintf(path, (size_t) PATH_MAX, "%s/%s", dirpath.c_str(), dp->d_name);
                if (dp->d_type == DT_DIR) {
                    deleteDir(path);
                } else {
                    unlink(path);
                }
            }
        }

        free(dentry);
        closedir(dirp);
        rmdir(dirpath.c_str());

        return false;
    }

    bool SharedFile::createFile(const std::string &filename)
    {
        int fd = -1;
        std::string filepath = DATA_DIR + "/" + filename;

        fd = TEMP_FAILURE_RETRY(open(filepath.c_str(), O_CREAT | O_RDWR | O_EXCL, S_IRUSR | S_IWUSR));
        int err = errno;
        if (-1 == fd) {
            LogError("Cannot create file. Error in open(): " << errnoToString(err));
            return true;
        }

        TEMP_FAILURE_RETRY(close(fd));

        return false;
    }

    bool SharedFile::openFile(const std::string &filename, int &fd)
    {
        std::string filepath = DATA_DIR + "/" + filename;

        fd = TEMP_FAILURE_RETRY(open(filepath.c_str(), O_RDWR, S_IRUSR | S_IWUSR));
        int err = errno;
        if (-1 == fd) {
            LogError("Cannot open file. Error in open(): " << errnoToString(err));
            return true;
        }

        return false;
    }

    bool SharedFile::deleteFile(const std::string &filename)
    {
        std::string filepath = DATA_DIR + "/" + filename;

        if (remove(filepath.c_str())) {
            LogError("Unable to delete file: " << filename.c_str() << " " << errnoToString(errno));
            return true;
        }

        return false;
    }

    bool SharedFile::setFileLabel(const std::string &filename, const std::string &label)
    {
        std::string filepath = DATA_DIR + "/" + filename;

        if (smack_setlabel(filepath.c_str(), label.c_str(), SMACK_LABEL_ACCESS)) {
            LogError("Cannot set SMACK label on file.");
            return true;
        }

        return false;
    }

    bool SharedFile::getFileLabel(const std::string &filename)
    {
        std::string filepath = DATA_DIR + "/" + filename;
        char *label = NULL;

        if (smack_check()) {
            if (0 != smack_getlabel(filepath.c_str(), &label, SMACK_LABEL_ACCESS)) {
                LogError("Unable to get smack label of process.");
                return true;
            }
        }

        if (label) {
            m_fileSmackLabel = label;
            free(label);
        } else
            m_fileSmackLabel.clear();

        return false;
    }

    bool SharedFile::setFileXattr(const std::string &filename, const std::string &xattr_value)
    {
        std::string filepath = DATA_DIR + "/" + filename;
        ssize_t count = 0;

        count = setxattr(filepath.c_str(), XATTR_NAME.c_str(), xattr_value.c_str(),
            xattr_value.size() + 1, XATTR_CREATE);

        if (count < 0) {
            LogError("Unable to set xattr on file.");
            return true;
        }

        return false;
    }

    bool SharedFile::getFileXattr(const std::string &filename)
    {
        std::string filepath = DATA_DIR + "/" + filename;
        char xattr_value[1024];
        ssize_t count = 0;

        count = getxattr(filepath.c_str(), XATTR_NAME.c_str(), xattr_value, sizeof(xattr_value));

        if (count < 0) {
            LogError("Unable to get xattr from file.");
            return true;
        }

        m_fileXattr = xattr_value;

        return false;
    }

    bool SharedFile::checkFileNameSyntax(const std::string &filename) const
    {
        std::size_t found = filename.find_first_not_of(ALLOWED_CHARS);

        if (found != std::string::npos || '-' == filename[0] ||
            '.' == filename[0]) {
            LogError("Illegal character in filename.");
            return true;
        }

        return false;
    }

    int SharedFile::openSharedFile(const std::string &filename,
        const std::string &client_label, int socket, int &fd)
    {
        if (checkFileNameSyntax(filename))
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

        if (m_sockCred.getCred(socket))
            return SECURITY_SERVER_API_ERROR_GETTING_SOCKET_LABEL_FAILED;

        if (fileExist(filename))
            return SECURITY_SERVER_API_ERROR_FILE_EXIST;

        LogSecureDebug("File: " << filename.c_str() << " does not exist.");

        if (createFile(filename))
            return SECURITY_SERVER_API_ERROR_FILE_CREATION_FAILED;

        if (setFileLabel(filename, m_sockCred.getLabel()))
            return SECURITY_SERVER_API_ERROR_SETTING_FILE_LABEL_FAILED;

        if (setFileXattr(filename, m_sockCred.getLabel()))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        if (openFile(filename, fd))
            return SECURITY_SERVER_API_ERROR_FILE_OPEN_FAILED;

        if (setFileLabel(filename, client_label.c_str()))
            return SECURITY_SERVER_API_ERROR_SETTING_FILE_LABEL_FAILED;

        return SECURITY_SERVER_API_SUCCESS;
    }

    int SharedFile::getFD(const std::string &filename, int socket, int &fd)
    {
        if (checkFileNameSyntax(filename))
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

        if (m_sockCred.getCred(socket))
            return SECURITY_SERVER_API_ERROR_AUTHENTICATION_FAILED;

        if (!fileExist(filename)) {
            LogSecureDebug("File: " << filename.c_str() << " does not exist.");

            if (createFile(filename))
                return SECURITY_SERVER_API_ERROR_SERVER_ERROR;
        }

        if (getFileLabel(filename))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        if (setFileLabel(filename, m_sockCred.getLabel()))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        if (openFile(filename, fd))
            return SECURITY_SERVER_API_ERROR_FILE_OPEN_FAILED;

        if (setFileLabel(filename, m_fileSmackLabel))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        return SECURITY_SERVER_API_SUCCESS;
    }

    int SharedFile::reopenSharedFile(const std::string &filename, int socket, int &fd)
    {
        if (checkFileNameSyntax(filename))
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

        if (m_sockCred.getCred(socket))
            return SECURITY_SERVER_API_ERROR_GETTING_SOCKET_LABEL_FAILED;

        if (!fileExist(filename))
            return SECURITY_SERVER_API_ERROR_FILE_NOT_EXIST;

        if (getFileLabel(filename))
            return SECURITY_SERVER_API_ERROR_GETTING_FILE_LABEL_FAILED;

        if (getFileXattr(filename))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        if (m_fileSmackLabel == m_sockCred.getLabel()) {
            if (openFile(filename, fd))
                return SECURITY_SERVER_API_ERROR_FILE_OPEN_FAILED;
        } else
            return SECURITY_SERVER_API_ERROR_AUTHENTICATION_FAILED;

        return SECURITY_SERVER_API_SUCCESS;
    }

    int SharedFile::deleteSharedFile(const std::string &filename, int socket)
    {
        if (checkFileNameSyntax(filename))
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

        if (m_sockCred.getCred(socket))
            return SECURITY_SERVER_API_ERROR_GETTING_SOCKET_LABEL_FAILED;

        if (!fileExist(filename))
            return SECURITY_SERVER_API_ERROR_FILE_NOT_EXIST;

        if (getFileLabel(filename))
            return SECURITY_SERVER_API_ERROR_GETTING_FILE_LABEL_FAILED;

        if (getFileXattr(filename))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        if ((m_fileSmackLabel == m_sockCred.getLabel()) || (m_fileXattr == m_sockCred.getLabel())) {
            if (deleteFile(filename))
                return SECURITY_SERVER_API_ERROR_FILE_DELETION_FAILED;
        } else
            return SECURITY_SERVER_API_ERROR_AUTHENTICATION_FAILED;

        return SECURITY_SERVER_API_SUCCESS;
    }


} //namespace SecurityServer
