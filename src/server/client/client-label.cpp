/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        client-label.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       This file contains implementation of security-server label API
 */

#include <cstring>
#include <dpl/log/log.h>
#include <dpl/exception.h>
#include <message-buffer.h>
#include <client-common.h>
#include <label-common.h>
#include <protocols.h>
#include <security-server.h>

SECURITY_SERVER_API
int security_server_label_access(const char *path, const char *new_label)
{
    using namespace SecurityServer;
    return try_catch([&] {
        if(NULL == path || !strlen(path)) {
            LogError("Error input param \"path\"");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if(NULL == new_label || !strlen(new_label)) {
            LogError("Error input param \"new_label\"");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        SockRAII sock;
        int retval = sock.Connect(SERVICE_SOCKET_LABEL);
        if (retval == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
            LogError("Access to socket denied.");
            return retval;
        } else if (retval != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Unable to connect to security-server, switching to offline mode");
            if (geteuid() != 0) {
                LogError("Offline mode is available only to root");
                return SECURITY_SERVER_API_ERROR_OPERATION_NOT_PERMITTED;
            }
            return labelAccess(path, new_label);
        }

        MessageBuffer send, recv;
        Serialization::Serialize(send, (int)LabelCall::SET_ACCESS_LABEL);
        Serialization::Serialize(send, std::string(path));
        Serialization::Serialize(send, std::string(new_label));

        // send buffer to server
        retval = sendToServerWithFd(sock.Get(), send.Pop(), recv);
        if (retval != SECURITY_SERVER_API_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        if (retval != SECURITY_SERVER_API_SUCCESS)
            return retval;

        return retval;
    });
}

SECURITY_SERVER_API
int security_server_label_transmute(const char *path, int transmute)
{
    using namespace SecurityServer;
    return try_catch([&] {
        if(NULL == path || !strlen(path)) {
            LogError("Error input param \"path\"");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if(transmute!=0 && transmute!=1) {
            LogError("Error input param \"transmute\"");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        SockRAII sock;
        int retval = sock.Connect(SERVICE_SOCKET_LABEL);
        if (retval == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
            LogError("Access to socket denied.");
            return retval;
        } else if (retval != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Unable to connect to security-server, switching to offline mode");
            if (geteuid() != 0) {
                LogError("Offline mode is available only to root");
                return SECURITY_SERVER_API_ERROR_OPERATION_NOT_PERMITTED;
            }
            return labelTransmute(path, transmute);
        }

        MessageBuffer send, recv;
        Serialization::Serialize(send, (int)LabelCall::SET_TRANSMUTE_FLAG);
        Serialization::Serialize(send, std::string(path));
        Serialization::Serialize(send, transmute);

        // send buffer to server
        retval = sendToServerWithFd(sock.Get(), send.Pop(), recv);
        if (retval != SECURITY_SERVER_API_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        if (retval != SECURITY_SERVER_API_SUCCESS)
            return retval;

        return retval;
    });
}
