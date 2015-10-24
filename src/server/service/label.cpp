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
 * @file        label.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       This function contain implementation of LabelService
 */

#include <memory>
#include <errno.h>
#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <protocols.h>
#include <security-server-error.h>
#include <security-server-util.h>
#include <error-description.h>
#include <fstream>
#include <label.h>
#include <label-common.h>
#include <string>
#include <sys/smack.h>

// interfaces ID
const int INTERFACE_SET_ATTR = 0;

namespace {

const char COMMENT = '#';
const char * const WHITESPACES = " \n\r\t\v";
const char *blacklist_file = "/usr/share/security-server/label-blacklist";
const char *whitelist_file = "/usr/share/security-server/label-whitelist";

void trim(std::string &s, const char *whitespaces)
{
    // trim left
    size_t startpos = s.find_first_not_of(whitespaces);
    if (startpos == std::string::npos) {
        s.clear();
        return;
    }
    s.erase(0, startpos);

    // trim right
    size_t endpos = s.find_last_not_of(whitespaces);
    s.erase(endpos+1);
}

bool check_label_present(const char *filename, const std::string &label)
{
    std::ifstream infile(filename);
    if (infile.is_open())
    {
        std::string line;
        while (std::getline(infile, line))
        {
            trim(line, WHITESPACES);
            if (line.empty())
                continue;
            if (line.at(0) == COMMENT)
                continue;
            if (line.compare(label) == 0)
                return true;
        }
    }
    return false;
}

int checkClientOnWhitelist(const std::string &label)
{
    if(!check_label_present(whitelist_file, label)) {
        LogWarning("Client " << label << " is not on whitelist");
        return SECURITY_SERVER_API_ERROR_LABEL_NOT_ON_WHITE_LIST;
    }
    return SECURITY_SERVER_API_SUCCESS;
}

bool getClientLabel(int fd, std::string &clientLabel)
{
    // identify calling client label
    char *clientLabelPtr = NULL;
    if (smack_new_label_from_socket(fd, &clientLabelPtr) < 0) {
        int error = errno;
        LogError("Failed to get new label from socket, error=" << SecurityServer::errnoToString(error));
        return false;
    }
    clientLabel = clientLabelPtr;
    return true;
}

bool getPathLabel(const std::string &path, std::string &retval)
{
    char *label = NULL;
    if (0 != smack_getlabel(path.c_str(), &label, SMACK_LABEL_ACCESS)) {
        LogError("Unable to get smack label of file/dir " << path);
        return true;
    }

    std::unique_ptr<char, decltype(std::free) *> labelPtr(label, std::free);
    retval = label ? label : "";
    return false;
}

int checkFileOnBlacklist(const std::string &path, const std::string &newLabel = "")
{
    // check if file can be modified
    std::string currentLabel;
    if (getPathLabel(path, currentLabel)) {
        return SECURITY_SERVER_API_ERROR_GETTING_FILE_LABEL_FAILED;
    }

    // check if old label not on blacklist
    if (check_label_present(blacklist_file, currentLabel.c_str())) {
        LogWarning("Current label " << currentLabel << " on file " << path << " is on blacklist");
        return SECURITY_SERVER_API_ERROR_LABEL_ON_BLACK_LIST;
    }

    // check if new label not on blacklist
    if (!newLabel.empty() && check_label_present(blacklist_file, newLabel.c_str())) {
        LogWarning("New label " << newLabel << " on file " << path << " is on blacklist");
        return SECURITY_SERVER_API_ERROR_LABEL_ON_BLACK_LIST;
    }
    return SECURITY_SERVER_API_SUCCESS;
}

} // namespace anonymous

namespace SecurityServer {

GenericSocketService::ServiceDescriptionVector LabelService::GetServiceDescription() {
    return ServiceDescriptionVector {
        {SERVICE_SOCKET_LABEL,            "security-server::label", INTERFACE_SET_ATTR }
    };
}

void LabelService::Start() {
    Create();
}

void LabelService::Stop() {
    Join();
}

void LabelService::accept(const AcceptEvent &event) {
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
}

void LabelService::write(const WriteEvent &event) {
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void LabelService::process(const ReadEvent &event) {
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while (processOne(event.connectionID, info.buffer, info.interfaceID));
}

void LabelService::close(const CloseEvent &event) {
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_connectionInfoMap.erase(event.connectionID.counter);
}

bool LabelService::processOne(const ConnectionID &conn, MessageBuffer &buffer, InterfaceID interfaceID)
{
    LogDebug("Iteration begin");
    // waiting for all data
    if (!buffer.Ready())
        return false;

    std::string clientLabel;
    if (smackRuntimeCheck() && !getClientLabel(conn.sock, clientLabel)) {
        LogError("Couldn't get client label");
        m_serviceManager->Close(conn);
        return false;
    }

    MessageBuffer send, recv;
    int ret;
    // receive data from buffer and check MSG_ID
    Try {
        int msgTypeInt;
        Deserialization::Deserialize(buffer, msgTypeInt);  // receive MSG_ID
        LabelCall msgType;
        msgType = static_cast<LabelCall>(msgTypeInt);

        // use received data
        if (interfaceID != INTERFACE_SET_ATTR) {
            LogWarning("Error, wrong interface");
            m_serviceManager->Close(conn);
            return false;
        }

        ret = checkClientOnWhitelist(clientLabel);
        if (ret != SECURITY_SERVER_API_SUCCESS) {
            buffer.Clear();
            Serialization::Serialize(send, ret);
            m_serviceManager->Write(conn, send.Pop());
            return false;
        }
        switch(msgType) {
        case LabelCall::SET_ACCESS_LABEL:
            LogDebug("Entering set ACCESS label server side handler");
            ret = accessLabelRequest(buffer);
            break;
        case LabelCall::SET_TRANSMUTE_FLAG:
            LogDebug("Entering set TRANSMUTE flag server side handler");
            ret = transmuteRequest(buffer);
            break;
        default:
            LogDebug("Error, unknown function called by client");
            m_serviceManager->Close(conn);
            return false;
        };
    } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    Serialization::Serialize(send, ret);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

int LabelService::accessLabelRequest(MessageBuffer &buffer)
{
    std::string path, label;
    Deserialization::Deserialize(buffer, path);
    Deserialization::Deserialize(buffer, label);

    LogDebug("Label request for path " << path << " with label " << label);

    int ret;
    if (smackRuntimeCheck()) {
        ret = checkFileOnBlacklist(path, label);
        if (ret != SECURITY_SERVER_API_SUCCESS) {
            return ret;
        }
    }

    ret = labelAccess(path, label);
    if (ret != SECURITY_SERVER_API_SUCCESS) {
        LogError("Labeling access label " << label << " on path " << path << " failed");
    }
    return ret;
}

int LabelService::transmuteRequest(MessageBuffer &buffer)
{
    std::string path;
    int transmute_flag;
    Deserialization::Deserialize(buffer, path);
    Deserialization::Deserialize(buffer, transmute_flag);

    LogDebug("Label request for path " << path << " with transmute " << (transmute_flag ? "on" : "off"));
    int ret;
    if (smackRuntimeCheck()) {
        ret = checkFileOnBlacklist(path);
        if (ret != SECURITY_SERVER_API_SUCCESS) {
            return ret;
        }
    }
    ret = labelTransmute(path, transmute_flag);
    if (ret != SECURITY_SERVER_API_SUCCESS) {
        LogError("Labeling transmute " << transmute_flag << " on path " << path << " failed");
    }
    return ret;
}
} // namespace SecurityServer

