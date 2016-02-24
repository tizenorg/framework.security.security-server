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

#include <security-server-error.h>
#include <security-server-util.h>
#include <privilege-control.h>
#include <error-description.h>

const std::string XATTR_NAME = "security.openfor.provider";
const std::string DATA_DIR = "/var/run/security-server";
const std::string ALLOWED_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ \
                                   abcdefghijklmnopqrstuvwxyz \
                                   0123456789._-";

namespace
{
std::string dirFilename(const std::string &dir,
                        const std::string &filename)
{
    return dir + "/" + filename;
}
bool fileExist(const std::string &filename)
{
    std::string filepath = dirFilename(DATA_DIR, filename);
    struct stat buf;

    return ((lstat(filepath.c_str(), &buf) == 0) &&
            (((buf.st_mode) & S_IFMT) != S_IFLNK));
}

bool dirExist(const std::string &dirpath)
{
    struct stat buf;

    return ((lstat(dirpath.c_str(), &buf) == 0) &&
            (((buf.st_mode) & S_IFMT) == S_IFDIR));
}

bool deleteDir(const std::string &dirpath)
{
    DIR *dirp;
    struct dirent *dentry;
    struct dirent *dp = NULL;
    char path[PATH_MAX];

    if ((dirp = opendir(dirpath.c_str())) == NULL) {
        LogError("Cannot open data directory. " << SecurityServer::errnoToString(errno));
        return true;
    }

    size_t len = offsetof(struct dirent, d_name) + pathconf(dirpath.c_str(),
                          _PC_NAME_MAX) + 1;
    dentry = (struct dirent*)malloc(len);

    if (!dentry) {
        LogError("Cannot open directory. Not enough memory!");
        closedir(dirp);
        return true;
    }

    while ((!readdir_r(dirp, dentry, &dp)) && dp) {
        if (strcmp(dp->d_name, ".") && strcmp(dp->d_name, "..")) {
            snprintf(path, (size_t) PATH_MAX, "%s/%s", dirpath.c_str(),
                     dp->d_name);
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

bool createFile(const std::string &filename)
{
    int fd = -1;
    std::string filepath = dirFilename(DATA_DIR, filename);

    fd = TEMP_FAILURE_RETRY(open(filepath.c_str(),
                            O_CREAT | O_RDWR | O_EXCL, S_IRUSR | S_IWUSR));
    int err = errno;
    if (-1 == fd) {
        LogError("Cannot create file. Error in open(" << filepath << "): "
                 << SecurityServer::errnoToString(err));
        return true;
    }

    TEMP_FAILURE_RETRY(close(fd));

    return false;
}

bool openFile(const std::string &filename, int &fd)
{
    std::string filepath = dirFilename(DATA_DIR, filename);

    fd = TEMP_FAILURE_RETRY(open(filepath.c_str(), O_RDWR, S_IRUSR | S_IWUSR));
    int err = errno;
    if (-1 == fd) {
        LogError("Cannot open file. Error in open(): " << SecurityServer::errnoToString(err));
        return true;
    }

    return false;
}

bool deleteFile(const std::string &filename)
{
    std::string filepath = dirFilename(DATA_DIR, filename);

    if (remove(filepath.c_str())) {
        LogError("Unable to delete file: " << filename.c_str() << " "
                 << SecurityServer::errnoToString(errno));
        return true;
    }

    return false;
}

bool setFileLabel(const std::string &filename, const std::string &label)
{
    std::string filepath = dirFilename(DATA_DIR, filename);

    if (smack_setlabel(filepath.c_str(), label.c_str(), SMACK_LABEL_ACCESS)) {
        LogError("Cannot set SMACK label on file.");
        return true;
    }

    return false;
}

bool setFileXattr(const std::string &filename, const std::string &xattr_value)
{
    std::string filepath = dirFilename(DATA_DIR, filename);
    ssize_t count = 0;

    count = setxattr(filepath.c_str(), XATTR_NAME.c_str(), xattr_value.c_str(),
        xattr_value.size() + 1, XATTR_CREATE);

    if (count < 0) {
        LogError("Unable to set xattr on file.");
        return true;
    }

    return false;
}

bool createClientDirectory(const std::string &client_label)
{
    std::string full_dir_path = dirFilename(DATA_DIR, client_label);
    if( !dirExist(full_dir_path) ) {
        if(0 != mkdir(full_dir_path.c_str(), 0700)) {
            LogError("Unable to create directory for label: " << client_label << ", error: " << SecurityServer::errnoToString(errno));
            return true;
        }
    }
    return false;
}

}

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
            if (PC_OPERATION_SUCCESS != ss_get_smack_label_from_process(m_cr.pid, label)) {
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
        if (!dirExist(DATA_DIR.c_str())) {
            if (mkdir(DATA_DIR.c_str(), 0700)) {
				LogError("Unable to create " << DATA_DIR);
			}
		}
        else {
            deleteDir(DATA_DIR.c_str());
            if (mkdir(DATA_DIR.c_str(), 0700)) {
				LogError("Unable to create " << DATA_DIR);
			}
        }
    }

    std::string SharedFile::generateDirPath(const std::string &label) {
        return dirFilename(DATA_DIR, label);
    }
    std::string SharedFile::generateFullPath(const std::string &label,
                                             const std::string &filename) {
        return dirFilename(DATA_DIR, dirFilename(label, filename));
    }

    void SharedFile::deleteFile(const std::string &label,
                                const std::string &filename)
    {
        ::deleteFile(SharedFile::generateFullPath(label, filename));
    }

    bool SharedFile::getFileLabel(const std::string &filename)
    {
        std::string filepath = dirFilename(DATA_DIR, filename);
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

    bool SharedFile::getFileXattr(const std::string &filename)
    {
        std::string filepath = dirFilename(DATA_DIR, filename);
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

    bool SharedFile::checkFileNameSyntax(const std::string &filename)
    {
        std::size_t found = filename.find_first_not_of(ALLOWED_CHARS);

        if (found != std::string::npos || '-' == filename[0] ||
            '.' == filename[0]) {
            return true;
        }

        return false;
    }

    int SharedFile::openSharedFile(const std::string &filename,
        const std::string &client_label, int socket, int &fd)
    {
        if (checkFileNameSyntax(filename)) {
            LogError("Illegal character in filename.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        if (m_sockCred.getCred(socket))
            return SECURITY_SERVER_API_ERROR_GETTING_SOCKET_LABEL_FAILED;

        if (createClientDirectory(client_label))
            return SECURITY_SERVER_API_ERROR_DIRECTORY_CREATION_FAILED;

        std::string dir_and_filename = dirFilename(client_label, filename);
        if (fileExist(dir_and_filename))
            return SECURITY_SERVER_API_ERROR_FILE_EXIST;

        LogSecureDebug("File: " << dir_and_filename.c_str() << " does not exist.");

        if (createFile(dir_and_filename))
            return SECURITY_SERVER_API_ERROR_FILE_CREATION_FAILED;

        if (setFileLabel(dir_and_filename, m_sockCred.getLabel()))
            return SECURITY_SERVER_API_ERROR_SETTING_FILE_LABEL_FAILED;

        if (setFileXattr(dir_and_filename, m_sockCred.getLabel()))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        if (openFile(dir_and_filename, fd))
            return SECURITY_SERVER_API_ERROR_FILE_OPEN_FAILED;

        if (setFileLabel(dir_and_filename, client_label.c_str()))
            return SECURITY_SERVER_API_ERROR_SETTING_FILE_LABEL_FAILED;

        return SECURITY_SERVER_API_SUCCESS;
    }

    int SharedFile::getFD(const std::string &filename, int socket, int &fd)
    {
        if (checkFileNameSyntax(filename)) {
            LogError("Illegal character in filename.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        if (m_sockCred.getCred(socket))
            return SECURITY_SERVER_API_ERROR_AUTHENTICATION_FAILED;

        std::string dir_and_filename = dirFilename(m_sockCred.getLabel(), filename);
        if (!fileExist(dir_and_filename)) {
            LogSecureDebug("File: " << dir_and_filename.c_str() << " does not exist.");

            if (createFile(dir_and_filename))
                return SECURITY_SERVER_API_ERROR_SERVER_ERROR;
        }

        if (getFileLabel(dir_and_filename))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        if (setFileLabel(dir_and_filename, m_sockCred.getLabel()))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        if (openFile(dir_and_filename, fd))
            return SECURITY_SERVER_API_ERROR_FILE_OPEN_FAILED;

        if (setFileLabel(dir_and_filename, m_fileSmackLabel))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        return SECURITY_SERVER_API_SUCCESS;
    }

    int SharedFile::reopenSharedFile(const std::string &filename, int socket, int &fd)
    {
        if (checkFileNameSyntax(filename)) {
            LogError("Illegal character in filename.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        if (m_sockCred.getCred(socket))
            return SECURITY_SERVER_API_ERROR_GETTING_SOCKET_LABEL_FAILED;

        std::string dir_and_filename = dirFilename(m_sockCred.getLabel(), filename);
        if (!fileExist(dir_and_filename))
            return SECURITY_SERVER_API_ERROR_FILE_NOT_EXIST;

        if (getFileLabel(dir_and_filename))
            return SECURITY_SERVER_API_ERROR_GETTING_FILE_LABEL_FAILED;

        if (getFileXattr(dir_and_filename))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        if (m_fileSmackLabel == m_sockCred.getLabel()) {
            if (openFile(dir_and_filename, fd))
                return SECURITY_SERVER_API_ERROR_FILE_OPEN_FAILED;
        } else
            return SECURITY_SERVER_API_ERROR_AUTHENTICATION_FAILED;

        return SECURITY_SERVER_API_SUCCESS;
    }

    int SharedFile::deleteSharedFile(const std::string &filename, int socket)
    {
        if (checkFileNameSyntax(filename)) {
            LogError("Illegal character in filename.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        if (m_sockCred.getCred(socket))
            return SECURITY_SERVER_API_ERROR_GETTING_SOCKET_LABEL_FAILED;

        std::string dir_and_filename = dirFilename(m_sockCred.getLabel(), filename);
        if (!fileExist(dir_and_filename))
            return SECURITY_SERVER_API_ERROR_FILE_NOT_EXIST;

        if (getFileLabel(dir_and_filename))
            return SECURITY_SERVER_API_ERROR_GETTING_FILE_LABEL_FAILED;

        if (getFileXattr(dir_and_filename))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        if ((m_fileSmackLabel == m_sockCred.getLabel()) ||
            (m_fileXattr == m_sockCred.getLabel())) {
            if (::deleteFile(dir_and_filename))
                return SECURITY_SERVER_API_ERROR_FILE_DELETION_FAILED;
        } else
            return SECURITY_SERVER_API_ERROR_AUTHENTICATION_FAILED;

        return SECURITY_SERVER_API_SUCCESS;
    }


} //namespace SecurityServer
