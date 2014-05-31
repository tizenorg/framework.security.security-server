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
 * @file        data-share.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementation of api-data-share service.
 */

#include <sys/smack.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <protocols.h>
#include <data-share.h>
#include <security-server.h>
#include <security-server-util.h>
#include <smack-check.h>

namespace SecurityServer {

GenericSocketService::ServiceDescriptionVector SharedMemoryService::GetServiceDescription() {
    return ServiceDescriptionVector
        {{SERVICE_SOCKET_SHARED_MEMORY, "security-server::api-data-share"}};
}

void SharedMemoryService::accept(const AcceptEvent &event) {
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);
}

void SharedMemoryService::write(const WriteEvent &event) {
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

bool SharedMemoryService::processOne(const ConnectionID &conn, MessageBuffer &buffer) {
    LogDebug("Iteration begin");
    static const char * const revoke = "-----";
    static const char * const permissions = "rwxat";
    char *providerLabel = NULL;
    std::string clientLabel;
    int clientPid = 0;
    int retCode = SECURITY_SERVER_API_ERROR_SERVER_ERROR;
    struct smack_accesses *smack = NULL;

    if (!buffer.Ready()) {
        return false;
    }

    Try {
        Deserialization::Deserialize(buffer, clientLabel);
        Deserialization::Deserialize(buffer, clientPid);
     } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    if (smack_check()) {
        if (0 != smack_new_label_from_socket(conn.sock, &providerLabel)) {
            LogDebug("Error in smack_new_label_from_socket");
            retCode = SECURITY_SERVER_API_ERROR_BAD_REQUEST;
            goto end;
        }

        if (!util_smack_label_is_valid(clientLabel.c_str())) {
            LogDebug("Invalid smack label: " << clientLabel);
            retCode = SECURITY_SERVER_API_ERROR_BAD_REQUEST;
            goto end;
        }

        if (smack_accesses_new(&smack)) {
            LogDebug("Error in smack_accesses_new");
            goto end;
        }

        if (smack_accesses_add_modify(smack, clientLabel.c_str(), providerLabel,
              permissions, revoke))
        {
            LogDebug("Error in smack_accesses_add_modify");
            goto end;
        }

        if (smack_accesses_apply(smack)) {
            LogDebug("Error in smack_accesses_apply");
            retCode = SECURITY_SERVER_API_ERROR_ACCESS_DENIED;
            goto end;
        }
        LogDebug("Access granted. Subject: " << clientLabel << " Provider: " << providerLabel);
    }
    retCode = SECURITY_SERVER_API_SUCCESS;
end:
    free(providerLabel);
    smack_accesses_free(smack);

    MessageBuffer sendBuffer;
    Serialization::Serialize(sendBuffer, retCode);
    m_serviceManager->Write(conn, sendBuffer.Pop());
    return true;
}

void SharedMemoryService::process(const ReadEvent &event) {
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &buffer = m_messageBufferMap[event.connectionID.counter];
    buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while(processOne(event.connectionID, buffer));
}

void SharedMemoryService::close(const CloseEvent &event) {
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_messageBufferMap.erase(event.connectionID.counter);
}

} // namespace SecurityServer

