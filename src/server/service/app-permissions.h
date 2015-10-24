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
 * @file        app-permissions.h
 * @author      Pawel Polawski (p.polawski@partner.samsung.com)
 * @version     1.0
 * @brief       This function contain header for implementation of security_server_app_enable_permissions
 *              and SS_app_disable_permissions on server side
 */

#ifndef _SECURITY_SERVER_APP_PERMISSIONS_
#define _SECURITY_SERVER_APP_PERMISSIONS_

#include <service-thread.h>
#include <generic-socket-manager.h>
#include <dpl/serialization.h>
#include <message-buffer.h>
#include <connection-info.h>
#include <protocols.h>
#include <transaction_manager.h>
#include <security-server-error.h>

#include <list>

namespace SecurityServer {

class AppPermissionsService  :
    public SecurityServer::GenericSocketService
  , public SecurityServer::ServiceThread<AppPermissionsService>
{
public:
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
    struct Transaction {
        enum Status {
            UNSET,
            BEGIN,
            END
        };

        Transaction() : status(Status::UNSET) {}
        operator bool() const {
            return status != Status::UNSET;
        }
        bool operator==(const ConnectionID &_conn) const {
            return status != Status::UNSET && _conn == conn;
        }
        bool operator!=(const ConnectionID &_conn) const {
            return status != Status::UNSET && _conn != conn;
        }
        void begin(const ConnectionID &_conn) {
            conn = _conn;
            status = Status::BEGIN;
        }
        void finish() {
            status = Status::END;
        }
        bool isEnded() const {
            return status == Status::END;
        }
        void unset() {
            status = Status::UNSET;
        }

        ConnectionID conn;
        Status status;
    };
    bool processOne(const ConnectionID &conn, MessageBuffer &buffer, InterfaceID interfaceID);

    static TransactionManager::Action toGenericAction(AppPermissionsAction action);
    void confirmTransaction(const std::vector<ConnectionID> &clients, int result = SECURITY_SERVER_API_SUCCESS);
    void confirmTransaction(const ConnectionID &client, int result = SECURITY_SERVER_API_SUCCESS);

    int processBegin(void);
    int processCommit(void);
    int processRollback(void);

    bool processPermissions(const ConnectionID &conn, MessageBuffer &buffer);
    bool processEnablePermission(const ConnectionID &conn, MessageBuffer &buffer);
    bool processDisablePermission(const ConnectionID &conn, MessageBuffer &buffer);
    bool processInstallApplication(const ConnectionID &conn, MessageBuffer &buffer);
    bool processUninstallApplication(const ConnectionID &conn, MessageBuffer &buffer);
    bool processRevokePermission(const ConnectionID &conn, MessageBuffer &buffer);
    bool processResetPermission(const ConnectionID &conn, MessageBuffer &buffer);
    bool processHasPermission(const ConnectionID &conn, MessageBuffer &buffer);
    bool processGetPermission(const ConnectionID &conn, MessageBuffer &buffer);
    bool processGetAppPermission(const ConnectionID &conn, MessageBuffer &buffer);
    bool processGetAppWithPermission(const ConnectionID &conn, MessageBuffer &buffer);
    bool processSetupPath(const ConnectionID &conn, MessageBuffer &buffer);
    bool processGetPath(const ConnectionID &conn, MessageBuffer &buffer);
    bool processRemovePath(const ConnectionID &conn, MessageBuffer &buffer);
    bool processAddFriend(const ConnectionID &conn, MessageBuffer &buffer);
    bool processDefinePermission(const ConnectionID &conn, MessageBuffer &buffer);
    bool processAdditionalRules(const ConnectionID &conn, MessageBuffer &buffer);
    bool processSetPrivilegeVersion(const ConnectionID &conn, MessageBuffer &buffer);
    bool processGetPrivilegeVersion(const ConnectionID &conn, MessageBuffer &buffer);
    bool processEnableBlacklist(const ConnectionID &conn, MessageBuffer &buffer);
    bool processDisableBlacklist(const ConnectionID &conn, MessageBuffer &buffer);
    bool processGetBlacklist(const ConnectionID &conn, MessageBuffer &buffer);
    bool processApplySharing(const ConnectionID &conn, MessageBuffer &buffer);
    bool processDropSharing(const ConnectionID &conn, MessageBuffer &buffer);

    bool processAppPermissionsChange(const ConnectionID &conn,
                                     AppPermissionsAction &checkType,
                                     MessageBuffer &buffer);
    bool processAppCheckAppPrivilege(const ConnectionID &conn,
                                     AppPermissionsAction &checkType,
                                     MessageBuffer &buffer);

    ConnectionInfoMap m_connectionInfoMap;
    TransactionManager m_transactionManager;
};

} // namespace SecurityServer

#endif // _SECURITY_SERVER_APP_ENABLE_PERMISSIONS_
