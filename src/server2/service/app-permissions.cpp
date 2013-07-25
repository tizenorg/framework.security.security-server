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
 * @file        app-permissions.cpp
 * @author      Pawel Polawski (pawel.polawski@partner.samsung.com)
 * @version     1.0
 * @brief       This function contain implementation of security_server_app_enable_permissions
 *              and security_server_app_disable_permissions on server side
 */

#include <memory>
#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <protocols.h>
#include <security-server.h>
#include <privilege-control.h>
#include <security-server-common.h>
#include <app-permissions.h>

namespace SecurityServer {

GenericSocketService::ServiceDescriptionVector AppPermissionsService::GetServiceDescription() {
    ServiceDescription sd = {
        "security-server::api-app-permissions",
        0,
        SERVICE_SOCKET_APP_PERMISSIONS
    };
    ServiceDescriptionVector v;
    v.push_back(sd);
    return v;
}

void AppPermissionsService::accept(const AcceptEvent &event) {
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);
}

void AppPermissionsService::write(const WriteEvent &event) {
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void AppPermissionsService::read(const ReadEvent &event) {
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &buffer = m_socketBufferMap[event.connectionID.counter];
    buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while(readOne(event.connectionID, buffer));
}

void AppPermissionsService::close(const CloseEvent &event) {
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_socketBufferMap.erase(event.connectionID.counter);
}

void AppPermissionsService::error(const ErrorEvent &event) {
    LogDebug("ErrorEvent. ConnectionID: " << event.connectionID.sock);
    m_serviceManager->Close(event.connectionID);
}

bool AppPermissionsService::readOne(const ConnectionID &conn, SocketBuffer &buffer)
{
    LogDebug("Iteration begin");
    SocketBuffer send, recv;
    Serialization serialization;
    Deserialization deserialization;
    std::vector<std::string> permissions_list;
    std::string app_id;
    int persistent;
    int i;
    int ret = SECURITY_SERVER_API_ERROR_SERVER_ERROR;
    app_type_t app_type;
    AppPermissionsAction appPermAction;

    //waiting for all data
    if (!buffer.Ready()) {
        return false;
    }

    LogDebug("Entering app_permissions server side handler");

    //receive data from buffer and check MSG_ID
    Try {
        deserialization.Deserialize(buffer, i);                 //receive MSG_ID
        appPermAction = (AppPermissionsAction)i;

        if (appPermAction == AppPermissionsAction::ENABLE)      //persistent is only in APP_ENABLE frame
            deserialization.Deserialize(buffer, persistent);

        deserialization.Deserialize(buffer, i);
        app_type = (app_type_t)i;
        deserialization.Deserialize(buffer, app_id);
        deserialization.Deserialize(buffer, permissions_list);
    } Catch (SocketBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    //+1 bellow is for NULL pointer at the end
    std::unique_ptr<const char *[]> perm_list (new (std::nothrow) const char *[permissions_list.size() + 1]);
    if (NULL == perm_list.get()) {
        LogError("Allocation error");
        m_serviceManager->Close(conn);
        return false;
    }

    //print received data
    LogDebug("app_type: " << (int)app_type);
    if (appPermAction == AppPermissionsAction::ENABLE)    //persistent is only in APP_ENABLE frame
        LogDebug("persistent: " << persistent);
    LogDebug("app_id: " << app_id);

    //left one free pointer for the NULL at the end
    for (i = 0; i < (int)permissions_list.size(); i++) {
        LogDebug("perm_list[" << i << "]: " << permissions_list[i]);
        perm_list[i] = (permissions_list[i]).c_str();
    }
    //put the NULL at the end
    perm_list[i] = NULL;

    //use received data
    if (appPermAction == AppPermissionsAction::ENABLE) {
        LogDebug("Calling app_enable_permiossions()");
        ret = perm_app_enable_permissions(app_id.c_str(), app_type, perm_list.get(), persistent);
        LogDebug("app_enable_permissions() returned: " << ret);
    } else {
        LogDebug("Calling app_disable_permiossions()");
        ret = perm_app_disable_permissions(app_id.c_str(), app_type, perm_list.get());
        LogDebug("app_disable_permissions() returned: " << ret);
    }

    //send response
    serialization.Serialize(send, ret);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

} // namespace SecurityServer

