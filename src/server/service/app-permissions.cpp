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
 * @file        app-permissions.cpp
 * @author      Pawel Polawski (pawel.polawski@partner.samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       This function contain implementation of security_server_app_enable_permissions
 *              and security_server_app_disable_permissions on server side
 */

#include <algorithm>
#include <memory>
#include <vector>
#include <string>
#include <sys/smack.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <security-server-error.h>
#include <privilege-control.h>
#include <permission-types.h>

#include <app-permissions.h>

namespace {

// interface ids
const SecurityServer::InterfaceID CHANGE_APP_PERMISSIONS = 0;
const SecurityServer::InterfaceID CHECK_APP_PRIVILEGE = 1;
const SecurityServer::InterfaceID PERMISSIONS = 2;

std::vector<const char*> toCTab(const std::vector<std::string> &data) {
    std::vector<const char*> tab(data.size() + 1, nullptr);
    size_t i;
    for (i = 0; i < data.size(); ++i)
        tab[i] = data[i].c_str();
    return tab;
}

struct CTab {
    char **m_data;

    CTab() : m_data(nullptr) {
    }

    ~CTab() {
        if (!m_data)
            return;
        size_t count = 0;
        while (m_data[count])
            free(m_data[count++]);
        free(m_data);
    }

    std::vector<std::string> get(void) const {
        size_t count = 0;
        if (m_data)
            while (m_data[count])
                count ++;
		else
			return std::vector<std::string>();
        return std::vector<std::string>(m_data, m_data + count);
    }
};

struct CPermAppStatusTab {
    perm_app_status_t *m_apps;
    size_t m_number;

    CPermAppStatusTab() : m_apps(nullptr), m_number(0U) {
    }

    ~CPermAppStatusTab() {
        if (!m_apps)
            return;
        for (size_t i = 0; i < m_number; ++i)
            free(m_apps[i].app_id);
        free(m_apps);
    }

    std::vector<perm_app_status_t> get(void) const {
        return std::vector<perm_app_status_t>(m_apps, m_apps + m_number);
    }
};

struct CPermBlackListStatusTab {
    perm_blacklist_status_t *m_perms;
    size_t m_number;

    CPermBlackListStatusTab() : m_perms(nullptr), m_number(0U) {
    }

    ~CPermBlackListStatusTab() {
        if (!m_perms)
            return;
        for (size_t i = 0; i < m_number; ++i)
            free(m_perms[i].permission_name);
        free(m_perms);
    }

    std::vector<perm_blacklist_status_t> get(void) const {
        return std::vector<perm_blacklist_status_t>(m_perms, m_perms + m_number);
    }
};

struct CStr {
    char *m_data;

    CStr() : m_data(nullptr) {
    }

    ~CStr() {
        free(m_data);
    }

    std::string get(void) const {
        if (!m_data)
                return std::string();
        return std::string(m_data);
    }
};

} // namespace anonymous

namespace SecurityServer {

GenericSocketService::ServiceDescriptionVector AppPermissionsService::GetServiceDescription() {
    return ServiceDescriptionVector {
        { SERVICE_SOCKET_APP_PERMISSIONS,
          "security-server::api-app-permissions",
          CHANGE_APP_PERMISSIONS },
        { SERVICE_SOCKET_APP_PRIVILEGE_BY_NAME,
          "security-server::api-app-privilege-by-name",
          CHECK_APP_PRIVILEGE },
        { SERVICE_SOCKET_PERMISSIONS,
          "security-server::api-permissions",
          PERMISSIONS }
    };
}

void AppPermissionsService::Start() {
    Create();
}

void AppPermissionsService::Stop() {
    Join();
}

void AppPermissionsService::accept(const AcceptEvent &event) {
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
}

void AppPermissionsService::write(const WriteEvent &event) {
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    if (event.left != 0)
        return;
    if (m_transactionManager.isClientTransactionFinished(event.connectionID)){
        m_serviceManager->Close(event.connectionID);
    }
}

void AppPermissionsService::process(const ReadEvent &event) {
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while(processOne(event.connectionID, info.buffer, info.interfaceID));
}

void AppPermissionsService::close(const CloseEvent &event) {
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    if (m_transactionManager.isDbLocked(TransactionManager::Transaction::Type::RW)
            && m_transactionManager.isActiveClient(event.connectionID)
            && !m_transactionManager.isClientTransactionFinished(event.connectionID)) {
        LogDebug("RW active client is breaking the connection");
        (void)processRollback();
    }
    m_transactionManager.unlockDb(event.connectionID);
    TransactionManager::ConnectionIDVector clientsToNotify =
            m_transactionManager.updateCurrentTransaction();
    // Only RW clients use libprivilege transactions
    if (clientsToNotify.size() == 1
            && m_transactionManager.isReadWriteClient(clientsToNotify.front()))
        confirmTransaction(clientsToNotify, processBegin());
    else
        confirmTransaction(clientsToNotify);
    m_connectionInfoMap.erase(event.connectionID.counter);
}

bool AppPermissionsService::processOne(const ConnectionID &conn,
                                       MessageBuffer &buffer,
                                       InterfaceID interfaceID)
{
    LogDebug("Iteration begin");

    //waiting for all data
    if (!buffer.Ready()) {
        return false;
    }

    LogDebug("Entering app_permissions server side handler");
    Try {
        switch(interfaceID) {
        case PERMISSIONS:
        case CHECK_APP_PRIVILEGE:
        case CHANGE_APP_PERMISSIONS:
            return processPermissions(conn, buffer);
        default:
            LogWarning("Unknown interfaceId. Closing socket.");
            m_serviceManager->Close(conn);
            return false;
        }
    } Catch (MessageBuffer::Exception::Base) {
        LogError("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }
}

TransactionManager::Action AppPermissionsService::toGenericAction(AppPermissionsAction action) {
    switch(action) {
    case AppPermissionsAction::BEGIN_RW:
        return TransactionManager::Action::BEGIN_RW;
    case AppPermissionsAction::BEGIN_RO:
        return TransactionManager::Action::BEGIN_RO;
    case AppPermissionsAction::COMMIT:
    case AppPermissionsAction::ROLLBACK:
        return TransactionManager::Action::END;
    case AppPermissionsAction::HAS_PERMISSION:
    case AppPermissionsAction::GET_PERMISSION:
    case AppPermissionsAction::GET_APPS_WITH_PERMISSION:
    case AppPermissionsAction::GET_APP_PERMISSION:
    case AppPermissionsAction::GET_PATH:
    case AppPermissionsAction::GET_PRIV_VERSION:
    case AppPermissionsAction::GET_BLACKLIST:
    case AppPermissionsAction::CHECK_GIVEN_APP:
    case AppPermissionsAction::CHECK_CALLER_APP:
        return TransactionManager::Action::ACTION_RO;
    default:
        return TransactionManager::Action::ACTION_RW;
    }
}

void AppPermissionsService::confirmTransaction(const std::vector<ConnectionID> &clients,
                                               int result)
{
    MessageBuffer send;
    for (auto & client: clients) {
        Serialization::Serialize(send, result);
        m_serviceManager->Write(client, send.Pop());
    }
}

void AppPermissionsService::confirmTransaction(const ConnectionID &conn, int result) {
    MessageBuffer send;
    Serialization::Serialize(send, result);
    m_serviceManager->Write(conn, send.Pop());
}

bool AppPermissionsService::processPermissions(const ConnectionID &conn,
                                               MessageBuffer &buffer) {
    AppPermissionsAction action;
    int action_int;

    LogDebug("Processing permissions request");
    Deserialization::Deserialize(buffer, action_int);
    action = static_cast<AppPermissionsAction>(action_int);
    TransactionManager::Action generic_action = toGenericAction(action);

    if (!m_transactionManager.checkClientAction(generic_action, conn)) {
        LogWarning("Illegal client action");
        m_serviceManager->Close(conn);
        return false;
    }
    std::vector<ConnectionID> clientsToNotify;
    switch(action) {
    case AppPermissionsAction::BEGIN_RW:
        clientsToNotify = m_transactionManager.lockDb(conn,
                                                      TransactionManager::Transaction::Type::RW);
        if (!clientsToNotify.empty())
            confirmTransaction(clientsToNotify, processBegin());
        break;
    case AppPermissionsAction::BEGIN_RO:
        clientsToNotify = m_transactionManager.lockDb(conn,
                                                      TransactionManager::Transaction::Type::RO);
        confirmTransaction(clientsToNotify);
        break;
    case AppPermissionsAction::COMMIT:
        m_transactionManager.finishClientTransaction(conn);
        if (m_transactionManager.isReadWriteClient(conn))
            confirmTransaction(conn, processCommit());
        else
            confirmTransaction(conn);
        break;
    case AppPermissionsAction::ROLLBACK:
        m_transactionManager.finishClientTransaction(conn);
        if (m_transactionManager.isReadWriteClient(conn))
            confirmTransaction(conn, processRollback());
        else
            confirmTransaction(conn);
        break;
    case AppPermissionsAction::PERM_ENABLE:
        return processEnablePermission(conn, buffer);
    case AppPermissionsAction::PERM_DISABLE:
        return processDisablePermission(conn, buffer);
    case AppPermissionsAction::INSTALL:
        return processInstallApplication(conn, buffer);
    case AppPermissionsAction::UNINSTALL:
        return processUninstallApplication(conn, buffer);
    case AppPermissionsAction::REVOKE:
        return processRevokePermission(conn, buffer);
    case AppPermissionsAction::RESET:
        return processResetPermission(conn, buffer);
    case AppPermissionsAction::HAS_PERMISSION:
        return processHasPermission(conn, buffer);
    case AppPermissionsAction::GET_PERMISSION:
        return processGetPermission(conn, buffer);
    case AppPermissionsAction::GET_APPS_WITH_PERMISSION:
        return processGetAppWithPermission(conn, buffer);
    case AppPermissionsAction::GET_APP_PERMISSION:
        return processGetAppPermission(conn, buffer);
    case AppPermissionsAction::SETUP_PATH:
        return processSetupPath(conn, buffer);
    case AppPermissionsAction::GET_PATH:
        return processGetPath(conn, buffer);
    case AppPermissionsAction::REMOVE_PATH:
        return processRemovePath(conn, buffer);
    case AppPermissionsAction::ADD_FRIEND:
        return processAddFriend(conn, buffer);
    case AppPermissionsAction::DEFINE_PERMISSION:
        return processDefinePermission(conn, buffer);
    case AppPermissionsAction::ADDITIONAL_RULES:
        return processAdditionalRules(conn, buffer);
    case AppPermissionsAction::SET_PRIV_VERSION:
        return processSetPrivilegeVersion(conn, buffer);
    case AppPermissionsAction::GET_PRIV_VERSION:
        return processGetPrivilegeVersion(conn, buffer);
    case AppPermissionsAction::ENABLE_BLACKLIST:
        return processEnableBlacklist(conn, buffer);
    case AppPermissionsAction::DISABLE_BLACKLIST:
        return processDisableBlacklist(conn, buffer);
    case AppPermissionsAction::GET_BLACKLIST:
        return processGetBlacklist(conn, buffer);
    case AppPermissionsAction::APPLY_SHARING:
        return processApplySharing(conn, buffer);
    case AppPermissionsAction::DROP_SHARING:
        return processDropSharing(conn, buffer);
    case AppPermissionsAction::CHECK_GIVEN_APP:
    case AppPermissionsAction::CHECK_CALLER_APP:
        return processAppCheckAppPrivilege(conn, action, buffer);
    case AppPermissionsAction::ENABLE:
    case AppPermissionsAction::DISABLE:
        return processAppPermissionsChange(conn, action, buffer);
    default:
        LogWarning("Unknown command");
        m_serviceManager->Close(conn);
        return false;
    }

    return true;
}

int AppPermissionsService::processBegin(void) {
    LogDebug("Processing transaction begin request");

    int result = ss_perm_begin();
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_begin" << " finished with privilege code: " << result
                             << ", converted to " << ss_code);
    return ss_code;
}

int AppPermissionsService::processCommit(void) {
    LogDebug("Processing transaction commit request");

    int result = ss_perm_end();
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_end" << " finished with privilege code: " << result
                           << ", converted to " << ss_code);
    return ss_code;
}

int AppPermissionsService::processRollback(void) {
    LogDebug("Processing transaction rollback request");

    int result = ss_perm_rollback();
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_rollback" << " finished with privilege code: " << result
                                << ", converted to " << ss_code);
    return ss_code;
}

bool AppPermissionsService::processEnablePermission(const ConnectionID &conn,
                                                    MessageBuffer &buffer)
{
    LogDebug("Processing enable permission request");

    std::string pkg_id;
    int app_type;
    std::vector<std::string> permissions_list;
    bool persistent;

    Deserialization::Deserialize(buffer, pkg_id);
    Deserialization::Deserialize(buffer, app_type);
    Deserialization::Deserialize(buffer, permissions_list);
    Deserialization::Deserialize(buffer, persistent);

    LogDebug("app_id: " << pkg_id);
    LogDebug("app_type: " << app_type);
    LogDebug("persistent: " << (persistent ? "true" : "false"));

    int result = ss_perm_app_enable_permissions(pkg_id.c_str(),
                                                static_cast<app_type_t>(app_type),
                                                toCTab(permissions_list).data(),
                                                persistent);
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_enable_permissions" << " finished with privilege code: " << result
                                              << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processDisablePermission(const ConnectionID &conn,
                                                     MessageBuffer &buffer)
{
    LogDebug("Processing disable permission request");

    std::string pkg_id;
    int app_type;
    std::vector<std::string> permissions_list;

    Deserialization::Deserialize(buffer, pkg_id);
    Deserialization::Deserialize(buffer, app_type);
    Deserialization::Deserialize(buffer, permissions_list);

    LogDebug("app_id: " << pkg_id);
    LogDebug("app_type: " << app_type);

    int result = ss_perm_app_disable_permissions(pkg_id.c_str(),
                                                static_cast<app_type_t>(app_type),
                                                toCTab(permissions_list).data());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_disable_permissions" << " finished with privilege code: " << result
                                               << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processInstallApplication(const ConnectionID &conn,
                                                      MessageBuffer &buffer)
{
    LogDebug("Processing install application request");

    std::string pkg_id;

    Deserialization::Deserialize(buffer, pkg_id);

    LogDebug("pkg_id: " << pkg_id);

    int result = ss_perm_app_install(pkg_id.c_str());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_install" << " finished with privilege code: " << result
                                   << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processUninstallApplication(const ConnectionID &conn,
                                                        MessageBuffer &buffer)
{
    LogDebug("Processing uninstall application request");

    std::string pkg_id;

    Deserialization::Deserialize(buffer, pkg_id);

    LogDebug("pkg_id: " << pkg_id);

    int result = ss_perm_app_uninstall(pkg_id.c_str());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_uninstall" << " finished with privilege code: " << result
                                     << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processRevokePermission(const ConnectionID &conn,
                                                    MessageBuffer &buffer)
{
    LogDebug("Processing revoke permission request");

    std::string pkg_id;

    Deserialization::Deserialize(buffer, pkg_id);

    LogDebug("pkg_id: " << pkg_id);

    int result = ss_perm_app_revoke_permissions(pkg_id.c_str());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_revoke_permissions" << " finished with privilege code: " << result
                                              << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processResetPermission(const ConnectionID &conn,
                                                   MessageBuffer &buffer)
{
    LogDebug("Processing reset permission request");

    std::string pkg_id;

    Deserialization::Deserialize(buffer, pkg_id);

    LogDebug("pkg_id: " << pkg_id);

    int result = ss_perm_app_reset_permissions(pkg_id.c_str());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_reset_permissions" << " finished with privilege code: " << result
                                             << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processHasPermission(const ConnectionID &conn, MessageBuffer &buffer)
{
    LogDebug("Processing has permission request");

    std::string pkg_id;
    int app_type;
    std::string permission_name;

    Deserialization::Deserialize(buffer, pkg_id);
    Deserialization::Deserialize(buffer, app_type);
    Deserialization::Deserialize(buffer, permission_name);

    LogDebug("pkg_id: " << pkg_id);
    LogDebug("app_type: " << app_type);
    LogDebug("permission_name: " << permission_name);

    bool enabled = false;
    int result = ss_perm_app_has_permission(pkg_id.c_str(),
                                            static_cast<app_type_t>(app_type),
                                            permission_name.c_str(),
                                            &enabled);
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_has_permission" << " finished with privilege code: " << result
                                          << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    Serialization::Serialize(send, enabled);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processGetPermission(const ConnectionID &conn, MessageBuffer &buffer)
{
    LogDebug("Processing get permission request");

    int app_type;

    Deserialization::Deserialize(buffer, app_type);

    LogDebug("app_type: " << app_type);

    CTab perm_list;
    int result = ss_perm_get_permissions(&perm_list.m_data,
                                         static_cast<app_type_t>(app_type));
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_get_permissions" << " finished with privilege code: " << result
                                       << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    Serialization::Serialize(send, perm_list.get());
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processGetAppWithPermission(const ConnectionID &conn,
                                                        MessageBuffer &buffer)
{
    LogDebug("Processing get apps with permission request");

    int app_type;
    std::string permission_name;

    Deserialization::Deserialize(buffer, app_type);
    Deserialization::Deserialize(buffer, permission_name);

    LogDebug("s_permission_name: " << permission_name);
    LogDebug("app_type: " << app_type);

    CPermAppStatusTab app_list;

    int result = ss_perm_get_apps_with_permission(&app_list.m_apps,
                                                  &app_list.m_number,
                                                  static_cast<app_type_t>(app_type),
                                                  permission_name.c_str());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_get_apps_with_permission" << " finished with privilege code: " << result
                                                << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    Serialization::Serialize(send, app_list.get());
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processGetAppPermission(const ConnectionID &conn,
                                                    MessageBuffer &buffer)
{
    LogDebug("Processing get app permissions request");

    std::string pkg_id;
    int app_type;

    Deserialization::Deserialize(buffer, pkg_id);
    Deserialization::Deserialize(buffer, app_type);

    LogDebug("app_id: " << pkg_id);
    LogDebug("app_type: " << app_type);

    CTab perm_list;
    int result = ss_perm_app_get_permissions(pkg_id.c_str(),
                                             static_cast<app_type_t>(app_type),
                                             &perm_list.m_data);
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_get_permissions" << " finished with privilege code: " << result
                                           << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    Serialization::Serialize(send, perm_list.get());
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processSetupPath(const ConnectionID &conn, MessageBuffer &buffer)
{
    LogDebug("Processing setup path request");

    std::string pkg_id;
    std::string path;
    int app_path_type;
    std::string label;

    Deserialization::Deserialize(buffer, pkg_id);
    Deserialization::Deserialize(buffer, path);
    Deserialization::Deserialize(buffer, app_path_type);

    LogDebug("app_id: " << pkg_id);
    LogDebug("path: " << path);
    LogDebug("app_path_type" << app_path_type);

    app_path_type_t path_type = static_cast<app_path_type_t>(app_path_type);
    switch(path_type) {
    case PERM_APP_PATH_GROUP:
    case PERM_APP_PATH_ANY_LABEL:
        Deserialization::Deserialize(buffer, label);
    default:
        break;
    }

    int result = ss_perm_app_setup_path(pkg_id.c_str(),
                                        path.c_str(),
                                        path_type,
                                        label.c_str());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_setup_path" << " finished with privilege code: " << result
                                      << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processGetPath(const ConnectionID &conn, MessageBuffer &buffer)
{
    LogDebug("Processing get paths request");

    std::string pkg_id;
    int app_path_type;

    Deserialization::Deserialize(buffer, pkg_id);
    Deserialization::Deserialize(buffer, app_path_type);

    LogDebug("app_id: " << pkg_id);
    LogDebug("app_path_type: " << app_path_type);

    CTab path_list;
    int result = ss_perm_app_get_paths(pkg_id.c_str(),
                                       static_cast<app_path_type_t>(app_path_type),
                                       &path_list.m_data);
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_get_paths" << " finished with privilege code: " << result
                                     << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    Serialization::Serialize(send, path_list.get());
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processRemovePath(const ConnectionID &conn, MessageBuffer &buffer)
{
    LogDebug("Processing remove path request");

    std::string pkg_id;
    std::string path;

    Deserialization::Deserialize(buffer, pkg_id);
    Deserialization::Deserialize(buffer, path);

    LogDebug("app_id: " << pkg_id);
    LogDebug("path: " << path);

    int result = ss_perm_app_remove_path(pkg_id.c_str(),
                                         path.c_str());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_remove_path" << " finished with privilege code: " << result
                                       << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processAddFriend(const ConnectionID &conn, MessageBuffer &buffer)
{
    LogDebug("Processing add friend request");

    std::string pkg_id1, pkg_id2;

    Deserialization::Deserialize(buffer, pkg_id1);
    Deserialization::Deserialize(buffer, pkg_id2);

    LogDebug("pkg_id1: " << pkg_id1);
    LogDebug("pkg_id2: " << pkg_id2);

    int result = ss_perm_app_add_friend(pkg_id1.c_str(),
                                        pkg_id2.c_str());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_add_friend" << " finished with privilege code: " << result
                                      << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processDefinePermission(const ConnectionID &conn,
                                                    MessageBuffer &buffer)
{
    LogDebug("Processing define permission request");

    int app_type;
    std::string api_feature_name, tizen_version;
    std::vector<std::string> rules;
    bool fast;

    Deserialization::Deserialize(buffer, app_type);
    Deserialization::Deserialize(buffer, api_feature_name);
    Deserialization::Deserialize(buffer, tizen_version);
    Deserialization::Deserialize(buffer, rules);
    Deserialization::Deserialize(buffer, fast);

    LogDebug("app_type: " << app_type);
    LogDebug("api_feature_name: " << api_feature_name);
    LogDebug("tizen_version: " << tizen_version);
    LogDebug("fast: " << (fast ? "true" : "false"));

    int result = ss_perm_define_permission(static_cast<app_type_t>(app_type),
                                           api_feature_name.c_str(),
                                           tizen_version.c_str(),
                                           toCTab(rules).data(),
                                           fast);
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_define_permission" << " finished with privilege code: " << result
                                         << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processAdditionalRules(const ConnectionID &conn,
                                                   MessageBuffer &buffer)
{
    LogDebug("Processing additional rules request");

    std::vector<std::string> rules;

    Deserialization::Deserialize(buffer, rules);

    LogDebug("Got " << rules.size() << " rules");

    int result = ss_perm_add_additional_rules(toCTab(rules).data());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_add_additional_rules" << " finished with privilege code: " << result
                                            << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processSetPrivilegeVersion(const ConnectionID &conn,
                                                       MessageBuffer &buffer)
{
    LogDebug("Processing set privilege version request");

    std::string app_label_name, version;

    Deserialization::Deserialize(buffer, app_label_name);
    Deserialization::Deserialize(buffer, version);

    LogDebug("s_app_label_name : " << app_label_name);
    LogDebug("s_version : " << version);

    int result = ss_perm_app_set_privilege_version(app_label_name.c_str(),
                                                   version.c_str());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_set_privilege_version" << " finished with privilege code: " << result
                                                 << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processGetPrivilegeVersion(const ConnectionID &conn,
                                                       MessageBuffer &buffer)
{
    LogDebug("Processing get privilege version request");

    std::string app_label_name;

    Deserialization::Deserialize(buffer, app_label_name);

    LogDebug("s_app_label_name : " << app_label_name);

    CStr version;
    int result = ss_perm_app_get_privilege_version(app_label_name.c_str(),
                                                   &version.m_data);
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_get_privilege_version" << " finished with privilege code: " << result
                                                 << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    Serialization::Serialize(send, version.get());
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processEnableBlacklist(const ConnectionID &conn, MessageBuffer &buffer)
{
    LogDebug("Processing enable blacklist permissions request");

    std::string app_label_name;
    int perm_type;
    std::vector<std::string> permissions;

    Deserialization::Deserialize(buffer, app_label_name);
    Deserialization::Deserialize(buffer, perm_type);
    Deserialization::Deserialize(buffer, permissions);

    LogDebug("s_app_label_name : " << app_label_name);
    LogDebug("perm_type : " << perm_type);

    int result = ss_perm_app_enable_blacklist_permissions(app_label_name.c_str(),
                                                          static_cast<app_type_t>(perm_type),
                                                          toCTab(permissions).data());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_enable_blacklist_permissions" << " finished with privilege code: "
                                                        << result
                                                        << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processDisableBlacklist(const ConnectionID &conn,
                                                    MessageBuffer &buffer)
{
    LogDebug("Processing disable blacklist permissions request");

    std::string app_label_name;
    int perm_type;
    std::vector<std::string> permissions;

    Deserialization::Deserialize(buffer, app_label_name);
    Deserialization::Deserialize(buffer, perm_type);
    Deserialization::Deserialize(buffer, permissions);

    LogDebug("s_app_label_name : " << app_label_name);
    LogDebug("perm_type : " << perm_type);

    int result = ss_perm_app_disable_blacklist_permissions(app_label_name.c_str(),
                                                           static_cast<app_type_t>(perm_type),
                                                           toCTab(permissions).data());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_disable_blacklist_permissions" << " finished with privilege code: "
                                                         << result
                                                         << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processGetBlacklist(const ConnectionID &conn, MessageBuffer &buffer)
{
    LogDebug("Processing get blacklist permissions request");

    std::string app_label_name;

    Deserialization::Deserialize(buffer, app_label_name);

    LogDebug("s_app_label_name : " << app_label_name);

    CPermBlackListStatusTab perm_list;
    int result = ss_perm_app_get_blacklist_statuses(app_label_name.c_str(),
                                                    &perm_list.m_perms,
                                                    &perm_list.m_number);
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_app_get_blacklist_statuses" << " finished with privilege code: " << result
                                                  << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    Serialization::Serialize(send, perm_list.get());
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processApplySharing(const ConnectionID &conn, MessageBuffer &buffer)
{
    LogDebug("Processing apply sharing request");

    std::string owner_label_name, receiver_label_name;
    std::vector<std::string> paths;

    Deserialization::Deserialize(buffer, paths);
    Deserialization::Deserialize(buffer, owner_label_name);
    Deserialization::Deserialize(buffer, receiver_label_name);

    LogDebug("s_app_label_name : " << owner_label_name);
    LogDebug("perm_type : " << receiver_label_name);
    LogDebug("path_list size : " << paths.size());

    int result = ss_perm_apply_sharing(toCTab(paths).data(), owner_label_name.c_str(),
                                       receiver_label_name.c_str());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_apply_sharing" << " finished with privilege code: " << result
                                     << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}
bool AppPermissionsService::processDropSharing(const ConnectionID &conn, MessageBuffer &buffer)
{
    LogDebug("Processing drop sharing request");

    std::string owner_label_name, receiver_label_name;
    std::vector<std::string> paths;

    Deserialization::Deserialize(buffer, paths);
    Deserialization::Deserialize(buffer, owner_label_name);
    Deserialization::Deserialize(buffer, receiver_label_name);

    LogDebug("s_app_label_name : " << owner_label_name);
    LogDebug("perm_type : " << receiver_label_name);
    LogDebug("path_list size : " << paths.size());

    int result = ss_perm_drop_sharing(toCTab(paths).data(), owner_label_name.c_str(),
                                      receiver_label_name.c_str());
    int ss_code = privilegeToSecurityServerError(result);
    LogDebug("ss_perm_drop_sharing" << " finished with privilege code: " << result
                                    << ", converted to " << ss_code);
    //send response
    MessageBuffer send;
    Serialization::Serialize(send, ss_code);
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

/*------------------------------------------------------------------------------------------------*/

bool AppPermissionsService::processAppPermissionsChange(const ConnectionID &conn,
                                                        AppPermissionsAction &appPermAction,
                                                        MessageBuffer &buffer)
{
    LogDebug("Processing permissions change request");

    MessageBuffer send;
    int result = SECURITY_SERVER_API_ERROR_DATABASE_LOCKED;

    std::vector<std::string> permissions_list;
    std::string app_id;
    int persistent;
    size_t iter;

    app_type_t app_type;

    if (appPermAction == AppPermissionsAction::ENABLE)      //persistent is only in APP_ENABLE frame
        Deserialization::Deserialize(buffer, persistent);

    int type;
    Deserialization::Deserialize(buffer, type);
    app_type = static_cast<app_type_t>(type);
    Deserialization::Deserialize(buffer, app_id);
    Deserialization::Deserialize(buffer, permissions_list);

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
    for (iter = 0; iter < permissions_list.size(); ++iter) {
        LogDebug("perm_list[" << iter << "]: " << permissions_list[iter]);
        perm_list[iter] = (permissions_list[iter]).c_str();
    }
    //put the NULL at the end
    perm_list[iter] = NULL;

    //use received data
    if (appPermAction == AppPermissionsAction::ENABLE) {
        LogDebug("Calling ss_perm_app_enable_permissions()");
        result = ss_perm_app_enable_permissions(app_id.c_str(), app_type, perm_list.get(), persistent);
        LogDebug("perm_app_enable_permissions() returned: " << result);
    } else if (appPermAction == AppPermissionsAction::DISABLE){
        LogDebug("Calling ss_perm_app_disable_permissions()");
        result = ss_perm_app_disable_permissions(app_id.c_str(), app_type, perm_list.get());
        LogDebug("ss_perm_app_disable_permissions() returned: " << result);
    } else {
        LogWarning("Unknown command");
        m_serviceManager->Close(conn);
        return false;
    }

    //send response
    Serialization::Serialize(send, privilegeToSecurityServerError(result));
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

bool AppPermissionsService::processAppCheckAppPrivilege(const ConnectionID &conn,
                                                        AppPermissionsAction &checkType,
                                                        MessageBuffer &buffer)
{
    LogDebug("Processing app privilege check request");

    MessageBuffer send;
    int result = SECURITY_SERVER_API_ERROR_DATABASE_LOCKED;

    std::string privilege_name;
    std::string app_id;
    app_type_t app_type;
    bool has_permission = false;
    //receive data from buffer

    if (checkType != AppPermissionsAction::CHECK_GIVEN_APP
            && checkType != AppPermissionsAction::CHECK_CALLER_APP) {
        LogWarning("Unknown command");
        m_serviceManager->Close(conn);
        return false;
    }
    LogDebug("App privilege check call type: "
             << (checkType == AppPermissionsAction::CHECK_GIVEN_APP ?
                 "CHECK_GIVEN_APP":"CHECK_CALLER_APP"));
    if (checkType == AppPermissionsAction::CHECK_GIVEN_APP) { //app_id present only in this case
        Deserialization::Deserialize(buffer, app_id); //get app id
    }
    int type;
    Deserialization::Deserialize(buffer, type); //get app type
    app_type = static_cast<app_type_t>(type);

    Deserialization::Deserialize(buffer, privilege_name); //get privilege name

    if (checkType == AppPermissionsAction::CHECK_CALLER_APP) { //get sender app_id in this case
        char *label = NULL;
        if (smack_new_label_from_socket(conn.sock, &label) < 0) {
            LogWarning("Error in smack_new_label_from_socket(): "
                     "client label is unknown. Sending error response.");
            Serialization::Serialize(send, SECURITY_SERVER_API_ERROR_GETTING_SOCKET_LABEL_FAILED);
            m_serviceManager->Write(conn, send.Pop());
            return false;
        } else {
            app_id = label;
            free(label);
        }
    } //end if

    //print received data
    LogDebug("app_id: " << app_id);
    LogDebug("app_type: " << static_cast<int>(app_type));
    LogDebug("privilege_name: " << privilege_name);

    LogDebug("Calling ss_perm_app_has_permission()");
    result = ss_perm_app_has_permission(app_id.c_str(), app_type, privilege_name.c_str(), &has_permission);
    LogDebug("ss_perm_app_has_permission() returned: " << result << " , permission enabled: " << has_permission);

    //send response
    Serialization::Serialize(send, privilegeToSecurityServerError(result));
    Serialization::Serialize(send, static_cast<int>(has_permission));
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

} // namespace SecurityServer
