/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        client-common.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file constains implementation of common types
 *              used in security server.
 */

#ifndef _SECURITY_SERVER_CLIENT_
#define _SECURITY_SERVER_CLIENT_

#include <unistd.h>

#include <vector>
#include <functional>

#include <message-buffer.h>

#define SECURITY_SERVER_API __attribute__((visibility("default")))

extern "C" {
    struct msghdr;
}

namespace SecurityServer {

typedef std::vector<unsigned char> RawBuffer;

int sendToServerWithFd(int fd, const RawBuffer &send, MessageBuffer &recv);

int sendToServer(char const * const interface, const RawBuffer &send, MessageBuffer &recv);

/*
 * sendToServerAncData is special case when we want to receive file descriptor
 * passed by Security Server on behalf of calling process. We can't get it with
 * MessageBuffer.
 *
 * This function should be called _ONLY_ in this particular case.
 *
 */
int sendToServerAncData(char const * const interface, const RawBuffer &send, struct msghdr &hdr);

/*
 * Decorator function that performs frequently repeated exception handling in
 * SS client API functions. Accepts lambda expression as an argument.
 */
int try_catch(const std::function<int()>& func);


class SockRAII {
public:
    SockRAII()
      : m_sock(-1)
    {}

    ~SockRAII() {
        if (m_sock > -1 )
            close(m_sock);
    }

    int Connect(char const * const interface);

    int Get() const {
        return m_sock;
    }

private:
    int m_sock;
};
} // namespace SecuritySever

#endif // _SECURITY_SERVER_CLIENT_