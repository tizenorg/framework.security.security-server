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
 * @file        open-for.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @version     1.0
 * @brief       Implementation of open-for service
 */

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <protocols.h>
#include <open-for.h>
#include <unistd.h>
#include <algorithm>
#include <dirent.h>
#include <sys/stat.h>
#include <security-server.h>
#include <security-server-util.h>
#include <fcntl.h>
#include <sys/inotify.h>
#include <error-description.h>

namespace {
// Service may open more than one socket.
// These ID's will be assigned to sockets
// and will be used only by service.
// When new connection arrives, AcceptEvent
// will be generated with proper ID to inform
// service about input socket.
//
// Please note: SocketManaged does not use it and
// does not check it in any way.
//
// If your service require only one socket
// (uses only one socket labeled with smack)
// you may ignore this ID (just pass 0)
const int SOCKET_ID_UNPRIVILEGED  = 0;
const int SOCKET_ID_PRIVILEGED    = 1;
const int SOCKET_ID_INOTIFY       = 2;

// non-recursive!
int compute_directory_size(const std::string &dir_path,
                           size_t & sum_bytes,
                           size_t & num_files)
{
    sum_bytes = 0;
    num_files = 0;

    DIR *d = opendir(dir_path.c_str());
    if(d == NULL) {
        // directory not present -> sure no bytes and files - can quit
        if(errno==ENOENT)
            return 0;
        // otherwise - error
        LogError("Failed to get directory " << dir_path
                 << " information, errno: " << errno);
        return SECURITY_SERVER_API_ERROR_QUOTA_STAT_FAILED;
    }

    int retcode = 0;
    errno = 0;
    for(dirent *de = readdir(d); de != NULL; de = readdir(d))
    {
        struct stat buf;
        std::string current_file = std::string(de->d_name);
        if(SecurityServer::SharedFile::checkFileNameSyntax(current_file))
            continue;
        std::string current_file_path = std::string(dir_path + "/"+current_file);
        retcode = stat(current_file_path.c_str(), &buf);
        if(retcode < 0) {
            retcode = SECURITY_SERVER_API_ERROR_QUOTA_STAT_FAILED;
            LogError("err check stat on: " << current_file_path
                     << " errno: " << retcode << "/" << errno);
            break;
        }
        sum_bytes += buf.st_size;
        num_files ++;
    }
    if(errno)
        retcode = SECURITY_SERVER_API_ERROR_QUOTA_STAT_FAILED;
    closedir(d);
    return retcode;
}
} // namespace anonymous

namespace SecurityServer {

OpenForService::OpenForService() : m_inotify_watch_fd(-1)
{
    m_inotify_watch_fd = inotify_init1(IN_NONBLOCK);
    if(m_inotify_watch_fd < 0) {
        int err = errno;
        LogError("Error in inotify_init: " << SecurityServer::errnoToString(err));
        ThrowMsg(Exception::InitFailed, "Error in inotify_init: " << SecurityServer::errnoToString(err));
    }
}

OpenForService::~OpenForService()
{
    for(auto i : m_watchInfoMap)
        inotify_rm_watch(m_inotify_watch_fd, i.first);
    m_watchInfoMap.clear();
    ::close(m_inotify_watch_fd);
}

OpenForService::OpenForConnInfo::~OpenForConnInfo() {
    std::for_each(descriptorsVector.begin(),descriptorsVector.end(), ::close);
}

GenericSocketService::ServiceDescriptionVector OpenForService::GetServiceDescription() {
    return ServiceDescriptionVector {
        {SERVICE_SOCKET_OPEN_FOR_UNPRIVILEGED, "*", SOCKET_ID_UNPRIVILEGED, true},
        {SERVICE_SOCKET_OPEN_FOR_PRIVILEGED, "security-server::api-open-for-privileged", SOCKET_ID_PRIVILEGED, true},
        {m_inotify_watch_fd, SOCKET_ID_INOTIFY, false}
    };
}

void OpenForService::accept(const AcceptEvent &event)
{
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
}

void OpenForService::write(const WriteEvent &event)
{
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void OpenForService::process(const ReadEvent &event)
{
    switch(event.interfaceID)
    {
        case SOCKET_ID_INOTIFY:
            processINotifyEvent(event.rawBuffer);
            break;

        default:
        // SOCKET_ID_PRIVILEGED:
        // SOCKET_ID_UNPRIVILEGED:
        {
            LogDebug("Read event for counter: " << event.connectionID.counter);
            auto &info = m_connectionInfoMap[event.connectionID.counter];
            info.buffer.Push(event.rawBuffer);
            info.interfaceID = event.interfaceID;

            // We can get several requests in one package.
            // Extract and process them all
            while(processOne(event.connectionID, info.buffer, info.interfaceID, info.descriptorsVector));
            break;
        }
    }
}

void OpenForService::close(const CloseEvent &event)
{
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    auto &descVector = m_connectionInfoMap[event.connectionID.counter].descriptorsVector;

    for (auto iter = descVector.begin(); iter != descVector.end(); ++iter)
        TEMP_FAILURE_RETRY(::close(*iter));

    m_connectionInfoMap.erase(event.connectionID.counter);
}

int OpenForService::addWatchToDirectory(const std::string &filename,
                                        const std::string &client_label,
                                        int & fd)
{
    // add watch to the directory
    std::string dir_path = SharedFile::generateDirPath(client_label);
    std::string full_path = SharedFile::generateFullPath(client_label, filename);
    if( addLookupWatch(full_path, dir_path) )
        return SECURITY_SERVER_API_ERROR_WATCH_ADD_TO_FILE_FAILED;
    return SECURITY_SERVER_API_SUCCESS;
}

bool OpenForService::processOne(const ConnectionID &conn,
                                MessageBuffer &buffer,
                                InterfaceID interfaceID,
                                std::vector<int> &descVector)
{
    LogDebug("Iteration begin");

    std::string filename;
    std::string client_label;
    OpenForHdrs msgType;
    MessageBuffer sendBuffer;

    int retCode = SECURITY_SERVER_API_ERROR_SERVER_ERROR;
    int fd = -1;

    if (!buffer.Ready())
        return false;

    Try {
        int msgTypeInt;
        Deserialization::Deserialize(buffer, msgTypeInt);  //receive MSG_ID
        msgType = static_cast<OpenForHdrs>(msgTypeInt);
        Deserialization::Deserialize(buffer, filename);
    } Catch (MessageBuffer::Exception::Base) {
        LogError("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    if (interfaceID == SOCKET_ID_UNPRIVILEGED) {
        switch(msgType) {
        case OpenForHdrs::OPEN:
        {
            LogDebug("Entering open-for OPEN server handler.");
            Deserialization::Deserialize(buffer, client_label);

            // check if number of files and bytes is within the limit
            size_t sum_size, files_present;
            retCode = compute_directory_size(SharedFile::generateDirPath(client_label),
                                             sum_size, files_present);
            if(retCode < 0)
                break;
            if(files_present >= SHARED_FILE_MAX_NUM)
            {
                LogWarning("current number of files (" << files_present
                           << ") exceeds limit of " << SHARED_FILE_MAX_NUM
                           << " for label: " << client_label);
                retCode = SECURITY_SERVER_API_ERROR_QUOTA_NUM_FILES;
                break;
            }
            if(sum_size >= SHARED_FILE_QUOTA)
            {
                LogWarning("current consumption of " << sum_size
                           << "[B] exceeds limit of " << SHARED_FILE_QUOTA
                           << "[B] for label: " << client_label);
                retCode = SECURITY_SERVER_API_ERROR_QUOTA_BYTES;
                break;
            }

            // create directory and a shared file
            retCode = m_sharedFile.openSharedFile(filename, client_label, conn.sock, fd);
            if(retCode != 0)
                break;

            // add watch to the directory [cleanup fd on error]
            retCode = addWatchToDirectory(filename, client_label, fd);
            if(retCode) {
                LogError("Error adding watch to file: " << filename);
                m_sharedFile.deleteFile(client_label, filename);
                ::close(fd);
                fd = -1;
            }
            break;
        }
        case OpenForHdrs::OPEN_DEPRECATED:
            LogDebug("Entering open-for OPEN-DEPRECATED server handler.");
            retCode = m_sharedFile.getFD(filename, conn.sock, fd);
            break;
        case OpenForHdrs::DELETE:
            LogDebug("Entering open-for DELETE server handler.");
            retCode = m_sharedFile.deleteSharedFile(filename, conn.sock);
            // watch closed by inotify notification
            break;
        default:
            LogDebug("Error, unknown function called by client");
            retCode = false;
            break;
        };
    } else if (interfaceID == SOCKET_ID_PRIVILEGED) {
        switch(msgType) {
        case OpenForHdrs::REOPEN:
            LogDebug("Entering open-for REOPEN server handler.");
            retCode = m_sharedFile.reopenSharedFile(filename, conn.sock, fd);
            break;
        default:
            LogError("Error, unknown function called by client.");
            break;
        };
    } else {
        LogDebug("Error, wrong interface");
        retCode = SECURITY_SERVER_API_ERROR_BAD_REQUEST;
    }

    if (fd != -1)
        descVector.push_back(fd);
    SendMsgData sendMsgData(retCode, fd);

    m_serviceManager->Write(conn, sendMsgData);

    return true;
}

OpenForService::WatchFileInfo::WatchFileInfo(const std::string &file_path,
                                             const std::string &dir_path)
    : file_path(file_path), dir_path(dir_path) {}

bool OpenForService::addLookupWatch(const std::string &file_path,
                                    const std::string &dir_path)
{
    if(file_path.empty() || dir_path.empty())
        return true;

    int wd = inotify_add_watch(m_inotify_watch_fd, file_path.c_str(),
                       IN_EXCL_UNLINK |  IN_DELETE_SELF | IN_MODIFY | IN_CLOSE);
    if(wd == -1)
    {
        LogError("Adding watch for: " << file_path << ", fail, errno: " << errno);
        return true;
    }
    m_watchInfoMap.insert(std::make_pair(wd, WatchFileInfo(file_path, dir_path)));
    LogSecureDebug("Adding watch: " << file_path << ", wd: " << wd
                   << ", num watches: " << m_watchInfoMap.size());
    return false;
}

void OpenForService::removeWatch(int wd)
{
    if (m_watchInfoMap.find(wd) == m_watchInfoMap.end() )
    {
        LogError("Attempt to remove unknown watch id: " << wd);
        return;
    }

    inotify_rm_watch(m_inotify_watch_fd, wd);
    m_watchInfoMap.erase(wd);
    LogSecureDebug("Removed watch with wd: " << wd << ", num watches: "
                   << m_watchInfoMap.size());
}

void OpenForService::processINotifyEvent(const RawBuffer & rawBuffer)
{
    if(rawBuffer.size() < sizeof(struct inotify_event)) {
        LogError("Error, invalid inotify packet size");
        return;
    }

    size_t current_byte = 0;
    while(current_byte < rawBuffer.size())
    {
        const struct inotify_event *event =
                reinterpret_cast<const struct inotify_event *>(&rawBuffer[current_byte]);
        current_byte += sizeof(struct inotify_event) + event->len;

        if(event->mask & IN_Q_OVERFLOW)
        {
            LogError("Critical inotify error: IN_Q_OVERFLOW!");
            // honestly, the only thing we can do here is.. nothing.
            // it *may* (not must) happen that some watch handles won't be closed.
            // this event is very unlikely (it may happen only when not reading data from the descriptor,
            // while writing many big files at once)
            continue;
        }

        if(m_watchInfoMap.find(event->wd) == m_watchInfoMap.end()) {
            if( !(event->mask&IN_IGNORED) )
                LogWarning("inotify received unknown wd: " << event->wd);
            continue;
        }

        WatchFileInfo & watch = m_watchInfoMap.at(event->wd);
        LogDebug("inotify event from: " << event->wd
                 << " which is: " << watch.file_path);

        // for close and delete - just remove the watch
        // for modify - check the space consumption
        if((event->mask&IN_CLOSE) ||
           (event->mask&IN_IGNORED) ||
           (event->mask&IN_UNMOUNT) ||
           (event->mask&IN_DELETE_SELF))
        {
            LogDebug("removing watch " << event->wd << " | " << watch.file_path);
            removeWatch(event->wd);
        }
        else if(event->mask&IN_MODIFY)
        {
            size_t sum_bytes, num_files;
            if(compute_directory_size(watch.dir_path, sum_bytes, num_files)>=0)
            {
                if(sum_bytes > SHARED_FILE_QUOTA) {
                    LogWarning("shared file quota exceeded for: " << watch.dir_path
                               << ", removing file: " << watch.file_path
                               << " (" << sum_bytes << ">" << SHARED_FILE_QUOTA << ")");
                    unlink(watch.file_path.c_str());
                }
            }
            else
                LogError("computing directory " << watch.dir_path
                         << " size failed, bypassing modify event");
        }
    }
}

} // namespace SecurityServer
