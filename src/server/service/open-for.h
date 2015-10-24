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
 * @file        open-for.h
 * @author      Zigniew Jasinski (z.jasinski@samsung.com)
 * @version     1.0
 * @brief       Implementation of open-for service
 */

#ifndef _SECURITY_SERVER_OPEN_FOR_
#define _SECURITY_SERVER_OPEN_FOR_

#include <map>
#include <string>
#include <service-thread.h>
#include <generic-socket-manager.h>
#include <message-buffer.h>

#include "open-for-manager.h"

namespace SecurityServer
{
    class OpenForService
      : public SecurityServer::GenericSocketService
      , public SecurityServer::ServiceThread<OpenForService>
    {
    public:
        class Exception {
        public:
            DECLARE_EXCEPTION_TYPE(SecurityServer::Exception, Base)
            DECLARE_EXCEPTION_TYPE(Base, InitFailed)
        };
        OpenForService();
        virtual ~OpenForService();

        //service functions
        ServiceDescriptionVector GetServiceDescription();

        void Start();
        void Stop();

        DECLARE_THREAD_EVENT(AcceptEvent, accept)
        DECLARE_THREAD_EVENT(WriteEvent, write)
        DECLARE_THREAD_EVENT(ReadEvent, process)
        DECLARE_THREAD_EVENT(CloseEvent, close)

        void accept(const AcceptEvent &event);
        void write(const WriteEvent &event);
        void process(const ReadEvent &event);
        void close(const CloseEvent &event);
    private:
        typedef std::vector<int> DescriptorVector;

        struct OpenForConnInfo {
            ~OpenForConnInfo();

            DescriptorVector descriptorsVector;
            MessageBuffer buffer;
            InterfaceID interfaceID;
        };
        typedef std::map<int, OpenForConnInfo> OpenForConnInfoMap;

        struct WatchFileInfo {
            WatchFileInfo(const std::string &file_path,
                          const std::string &dir_path);

            std::string     file_path;
            std::string     dir_path;
        };
        typedef std::map<int, WatchFileInfo> WatchInfoMap; // wd -> struct
        bool addLookupWatch(const std::string &file_path,
                            const std::string &dir_path);
        void removeWatch(int wd);

        //internal service functions
        int addWatchToDirectory(const std::string &filename,
                                const std::string &client_label);
        bool processOne(const ConnectionID &conn,
                        MessageBuffer &buffer,
                        InterfaceID interfaceID,
                        DescriptorVector &descVector);
        void processINotifyEvent(const RawBuffer & rawBuffer);

        OpenForConnInfoMap m_connectionInfoMap;
        WatchInfoMap m_watchInfoMap;
        SharedFile m_sharedFile;
        int m_inotify_watch_fd;

    };
} // namespace SecurityServer

#endif // _SECURITY_SERVER_OPEN_FOR_
