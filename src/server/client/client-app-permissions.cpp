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
 * @file        client-app-permissions.cpp
 * @author      Pawel Polawski (pawel.polawski@partner.samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       This file contain implementation of security_server_app_enable_permissions
 *              and security_server_app_disable functions
 */


#include <cstring>
#include <cstdio>
#include <sys/types.h>
#include <unistd.h>
#include <new>

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>
#include <configuration.h>

#include <privilege-control.h>
#include <security-server.h>
#include <security-server-perm.h>
#include <permission-types.h>

struct ss_transaction {
    ss_transaction() : offlineMode(false) {}
    SecurityServer::SockRAII sock;
    bool offlineMode;
};

enum class TransactionType {
    RW,
    RO
};

typedef std::unique_ptr<ss_transaction> TransactionPtr;

static bool checkCaller() {
    return geteuid() == 0;
}

static int createTransaction(TransactionPtr &trans,
                             TransactionType type,
                             bool local = true,
                             const std::string &interface = SecurityServer::SERVICE_SOCKET_PERMISSIONS,
                             bool offline = false)
{
    using namespace SecurityServer;

    trans.reset(new ss_transaction());

    int ret;
    if (!offline) {
        ret = trans->sock.Connect(interface.c_str());
        if (ret != SECURITY_SERVER_API_SUCCESS) {
            LogWarning("Error connecting to security-server. Error code " << ret);
            offline = true;
        }
    }

    if (offline) {
        if (!checkCaller()) {
            LogWarning("Caller doesn't have permission to switch to offline"
                       " mode. Proceeding anyway.");
        }
        trans->offlineMode = true;

        if (local)
            return SECURITY_SERVER_API_SUCCESS;
        return privilegeToSecurityServerError(ss_perm_begin());
    }

    MessageBuffer send, recv;
    AppPermissionsAction action;
    if (type == TransactionType::RW)
        action = AppPermissionsAction::BEGIN_RW;
    else
        action = AppPermissionsAction::BEGIN_RO;
    Serialization::Serialize(send, static_cast<int>(action));
    ret = sendToServerWithFd(trans->sock.Get(), send.Pop(), recv);
    if (ret != SECURITY_SERVER_API_SUCCESS) {
        LogError("Error in sendToServer. Error code: " << ret);
        return ret;
    }
    int response;
    Deserialization::Deserialize(recv, response);
    if (response != SECURITY_SERVER_API_SUCCESS) {
        LogError("Error creating transaction. Error code: " << response);
        return response;
    }
    return SECURITY_SERVER_API_SUCCESS;
}

static int commitTransaction(TransactionPtr &trans, bool local = true) {
    using namespace SecurityServer;

    if (trans->offlineMode) {
        LogDebug("commit transaction in offline mode");
        if (local)
            return SECURITY_SERVER_API_SUCCESS;
        return privilegeToSecurityServerError(ss_perm_end());
    }

    MessageBuffer send, recv;
    Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::COMMIT));
    int result = sendToServerWithFd(trans->sock.Get(), send.Pop(), recv);
    if (result != SECURITY_SERVER_API_SUCCESS) {
        LogError("Error in sendToServer. Error code: " << result);
        return result;
    }

    int response;
    Deserialization::Deserialize(recv, response);
    if (response != SECURITY_SERVER_API_SUCCESS) {
        LogError("Error commiting transaction. Error code: " << response);
        return response;
    }
    return SECURITY_SERVER_API_SUCCESS;
}

static int rollbackTransaction(TransactionPtr &trans, bool local = true) {
    using namespace SecurityServer;

    if (trans->offlineMode) {
        LogDebug("rollback transaction in offline mode");
        if (local)
            return SECURITY_SERVER_API_SUCCESS;
        return privilegeToSecurityServerError(ss_perm_rollback());
    }

    MessageBuffer send, recv;
    Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::ROLLBACK));
    int result = sendToServerWithFd(trans->sock.Get(), send.Pop(), recv);
    if (result != SECURITY_SERVER_API_SUCCESS) {
        LogError("Error in sendToServer. Error code: " << result);
        return result;
    }

    int response;
    Deserialization::Deserialize(recv, response);
    if (response != SECURITY_SERVER_API_SUCCESS) {
        LogError("Error commiting transaction. Error code: " << response);
        return response;
    }
    return SECURITY_SERVER_API_SUCCESS;
}

static int security_server_perm_begin_internal(ss_transaction **transaction, bool offline) {
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_begin() called");

        if (transaction == nullptr || *transaction != nullptr) {
            LogWarning("transaction placeholder is NULL or transaction is already started");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        TransactionPtr trans;
        int ret = createTransaction(trans,
                                    TransactionType::RW,
                                    false,
                                    SecurityServer::SERVICE_SOCKET_PERMISSIONS,
                                    offline);

        if (ret != SECURITY_SERVER_API_SUCCESS) {
            LogError("Failed to create transaction");
            return ret;
        }

        *transaction = trans.release();
        return SECURITY_SERVER_API_SUCCESS;
    });
}

SECURITY_SERVER_API
int security_server_perm_begin(ss_transaction **transaction) {
    return security_server_perm_begin_internal(transaction, false);
}

SECURITY_SERVER_API
int security_server_perm_begin_offline(ss_transaction **transaction) {
    return security_server_perm_begin_internal(transaction, true);
}

SECURITY_SERVER_API
int security_server_perm_commit(ss_transaction **transaction) {
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_commit() called");

        if (transaction == nullptr || *transaction == nullptr) {
            LogWarning("transaction is NULL or transaction is not yet started");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        std::unique_ptr<ss_transaction> trans_ptr(*transaction);
        *transaction = nullptr;

        return commitTransaction(trans_ptr, false);

    });
}

SECURITY_SERVER_API
int security_server_perm_rollback(ss_transaction **transaction) {
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_rollback() called");

        if (transaction == nullptr || *transaction == nullptr) {
            LogWarning("transaction is NULL or transaction is not yet started");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        std::unique_ptr<ss_transaction> trans_ptr(*transaction);
        *transaction = nullptr;

        return rollbackTransaction(trans_ptr, false);
    });
}

SECURITY_SERVER_API
int security_server_perm_app_install(ss_transaction *transaction, const char *pkg_id) {
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_install() called");

        if (nullptr == pkg_id) {
            LogWarning("Application identifier is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("app_id: " << pkg_id);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_install() in offline mode");
            result = privilegeToSecurityServerError(ss_perm_app_install(pkg_id));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_install() failed. Error code: " << result);
            }
        } else {
            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::INSTALL));
            Serialization::Serialize(send, std::string(pkg_id));

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_install. Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_app_uninstall(ss_transaction *transaction, const char *pkg_id) {
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_uninstall() called");

        if (nullptr == pkg_id) {
            LogWarning("Application identifier is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("app_id: " << pkg_id);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_uninstall() in offline mode");
            result = privilegeToSecurityServerError(ss_perm_app_uninstall(pkg_id));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_uninstall() failed. Error code: " << result);
            }
        } else {
            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::UNINSTALL));
            Serialization::Serialize(send, std::string(pkg_id));

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_uninstall. Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}


SECURITY_SERVER_API
int security_server_perm_app_enable_permissions(ss_transaction *transaction,
                                                const char* pkg_id,
                                                app_type_t app_type,
                                                const char** perm_list,
                                                bool persistent)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_app_enable_permissions() called");

        if (pkg_id == nullptr) {
            LogWarning("Application identifier is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (perm_list == nullptr) {
            LogWarning("Permission list is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("app_id: " << pkg_id);
        LogDebug("app_type: " << app_type);
        LogDebug("persistent: " << (persistent ? "true" : "false"));
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_enable_permissions() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_app_enable_permissions(pkg_id, app_type, perm_list, persistent));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_enable_permissions() failed");
            }
        } else {
            //put all strings in STL vector
            std::vector<std::string> permissions_list;
            for (int i = 0; perm_list[i] != nullptr; i++) {
                LogDebug("perm_list[" << i << "]: " << perm_list[i]);
                permissions_list.push_back(std::string(perm_list[i]));
            }

            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::PERM_ENABLE));
            Serialization::Serialize(send, std::string(pkg_id));
            Serialization::Serialize(send, static_cast<int>(app_type));
            Serialization::Serialize(send, permissions_list);
            Serialization::Serialize(send, persistent);

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_enable_permissions."
                         " Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_app_disable_permissions(ss_transaction *transaction,
                                                 const char* pkg_id,
                                                 app_type_t app_type,
                                                 const char** perm_list)
{

    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_disable_permissions() called");

        if (pkg_id == nullptr) {
            LogWarning("Application identifier is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (perm_list == nullptr) {
            LogWarning("Permission list is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("app_id: " << pkg_id);
        LogDebug("app_type: " << app_type);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_disable_permissions() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_app_disable_permissions(pkg_id, app_type, perm_list));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_disable_permissions() failed. Error code: " << result);
            }
        } else {
            //put all strings in STL vector
            std::vector<std::string> permissions_list;
            for (int i = 0; perm_list[i] != nullptr; i++) {
                LogDebug("perm_list[" << i << "]: " << perm_list[i]);
                permissions_list.push_back(std::string(perm_list[i]));
            }

            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::PERM_DISABLE));
            Serialization::Serialize(send, std::string(pkg_id));
            Serialization::Serialize(send, static_cast<int>(app_type));
            Serialization::Serialize(send, permissions_list);

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_disable_permissions."
                         " Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_app_revoke_permissions(ss_transaction *transaction, const char* pkg_id) {
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_revoke_permissions() called");

        if (nullptr == pkg_id) {
            LogWarning("Application identifier is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("pkg_id: " << pkg_id);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_revoke_permissions() in offline mode");
            result = privilegeToSecurityServerError(ss_perm_app_revoke_permissions(pkg_id));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_revoke_permissions() failed. Error code: " << result);
            }
        } else {
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::REVOKE));
            Serialization::Serialize(send, std::string(pkg_id));

            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_revoke_permissions."
                         " Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_app_reset_permissions(ss_transaction *transaction, const char* pkg_id) {
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_reset_permissions() called");

        if (nullptr == pkg_id) {
            LogWarning("Application identifier is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("pkg_id: " << pkg_id);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_reset_permissions() in offline mode");
            result = privilegeToSecurityServerError(ss_perm_app_reset_permissions(pkg_id));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_reset_permissions() failed. Error code: " << result);
            }
        } else {
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::RESET));
            Serialization::Serialize(send, std::string(pkg_id));
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_reset_permissions."
                         " Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_app_has_permission(ss_transaction *transaction,
                                            const char *pkg_id,
                                            app_type_t app_type,
                                            const char *permission_name,
                                            bool *is_enabled)
{
    using namespace SecurityServer;
    return try_catch([&] {
        LogDebug("security_server_perm_app_has_permission() called");

        if (is_enabled == nullptr) {
            LogWarning("is_enabled placeholder is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (pkg_id == nullptr) {
            LogWarning("Application identifier is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (permission_name == nullptr) {
            LogWarning("Permission name is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RO);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("pkg_id: " << pkg_id);
        LogDebug("app_type: " << app_type);
        LogDebug("permission_name: " << permission_name);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_has_permission() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_app_has_permission(pkg_id, app_type, permission_name, is_enabled));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_has_permission() failed. Error code: " << result);
            }
        } else {
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::HAS_PERMISSION));
            Serialization::Serialize(send, std::string(pkg_id));
            Serialization::Serialize(send, static_cast<int>(app_type));
            Serialization::Serialize(send, std::string(permission_name));

            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_has_permission."
                         " Error code: " << result);
            } else {
                bool enabled;
                Deserialization::Deserialize(recv, enabled);
                *is_enabled = enabled;
            }
        }

        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

static int deserializeGetPermissions(SecurityServer::MessageBuffer &recv, char ***ppp_permissions) {
    using namespace SecurityServer;
    std::vector<std::string> permissions;
    Deserialization::Deserialize(recv, permissions);

    char **pp_permissions = (char **) calloc ((permissions.size() + 1), sizeof (char*));
    if (pp_permissions == nullptr) {
        LogError("calloc failed");
        return SECURITY_SERVER_API_ERROR_OUT_OF_MEMORY;
    }
    bool failed = false;
    size_t i;
    for (i = 0; i < permissions.size(); ++i) {
        pp_permissions[i] = strdup(permissions[i].c_str());
        if (pp_permissions[i] == nullptr) {
            LogError("Failed to copy string");
            failed = true;
            break;
        }
    }
    if (failed) {
        for(size_t j = 0; j < i; j++) {
            free(pp_permissions[j]);
        }
        free(pp_permissions);
        return SECURITY_SERVER_API_ERROR_OUT_OF_MEMORY;
    }

    *ppp_permissions = pp_permissions;
    return SECURITY_SERVER_API_SUCCESS;
}

SECURITY_SERVER_API
int security_server_perm_get_permissions(ss_transaction *transaction,
                                         char ***ppp_permissions,
                                         app_type_t app_type)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_get_permissions() called");

        if (ppp_permissions == nullptr) {
            LogWarning("Permissions placeholder is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RO);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("app_type: " << app_type);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_get_permissions() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_get_permissions(ppp_permissions, app_type));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_get_permissions() failed. Error code: " << result);
            }
        } else {
            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::GET_PERMISSION));
            Serialization::Serialize(send, static_cast<int>(app_type));

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_get_permissions."
                         " Error code: " << result);
            } else {
                result = deserializeGetPermissions(recv, ppp_permissions);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

static int deserializeGetAppsWithPermission(SecurityServer::MessageBuffer &recv,
                                            perm_app_status_t **pp_apps,
                                            size_t *pi_apps_number) {
    using namespace SecurityServer;
    int apps_cnt;
    Deserialization::Deserialize(recv, apps_cnt);
    if (apps_cnt == 0) {
        *pp_apps = nullptr;
        *pi_apps_number = 0;
        return SECURITY_SERVER_API_SUCCESS;
    }
    int copied_cnt = 0;
    auto free_list = std::bind(security_server_perm_free_apps_list, std::placeholders::_1,
                               std::ref(copied_cnt));
    std::unique_ptr<perm_app_status_t, decltype (free_list)>
        permAppStatusArr(static_cast<perm_app_status_t*>(malloc(apps_cnt * sizeof(perm_app_status_t))),
                         free_list);

    for (int i = 0; i < apps_cnt; ++i) {
        Deserialization::Deserialize(recv, permAppStatusArr.get()[i]);
    }

    *pp_apps = permAppStatusArr.release();
    *pi_apps_number = apps_cnt;
    return SECURITY_SERVER_API_SUCCESS;
}


SECURITY_SERVER_API
int security_server_perm_get_apps_with_permission(ss_transaction *transaction,
                                                  perm_app_status_t **pp_apps,
                                                  size_t *pi_apps_number,
                                                  app_type_t app_type,
                                                  const char *s_permission_name)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_get_apps_with_permission() called");

        if (pp_apps == nullptr) {
            LogWarning("Applications placeholder is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        if (pi_apps_number == nullptr) {
            LogWarning("Applications number placeholder is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        if (s_permission_name == nullptr) {
            LogWarning("Permission name is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RO);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("s_permission_name: " << s_permission_name);
        LogDebug("app_type: " << app_type);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_get_apps_with_permission() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_get_apps_with_permission(pp_apps, pi_apps_number,
                                                         app_type, s_permission_name));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_get_apps_with_permission() failed. Error code: " << result);
            }
        } else {
            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send,
                    static_cast<int>(AppPermissionsAction::GET_APPS_WITH_PERMISSION));
            Serialization::Serialize(send, static_cast<int>(app_type));
            Serialization::Serialize(send, std::string(s_permission_name));

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_get_apps_with_permission."
                         " Error code: " << result);
            } else {
                result = deserializeGetAppsWithPermission(recv, pp_apps, pi_apps_number);
            }
        }

        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {
            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
void security_server_perm_free_apps_list(perm_app_status_t *pp_apps, size_t i_apps_number) {
    if (pp_apps == nullptr)
        return;
    for (size_t i = 0; i < i_apps_number; i++)
        free(pp_apps[i].app_id);
    free(pp_apps);
}

static int deserializeAppGetPermissions(SecurityServer::MessageBuffer &recv,
                                        char ***ppp_permissions)
{
    using namespace SecurityServer;
    std::vector<std::string> permissions;
    Deserialization::Deserialize(recv, permissions);

    char **pp_permissions = (char **) calloc ((permissions.size() + 1), sizeof (char*));
    if (pp_permissions == nullptr) {
        LogError("calloc failed");
        return SECURITY_SERVER_API_ERROR_OUT_OF_MEMORY;
    }
    bool failed = false;
    size_t i;
    for (i = 0; i < permissions.size(); ++i) {
        pp_permissions[i] = strdup(permissions[i].c_str());
        if (pp_permissions[i] == nullptr) {
            LogError("Failed to copy string");
            failed = true;
            break;
        }
    }
    if (failed) {
        for(size_t j = 0; j < i; j++) {
            free(pp_permissions[j]);
        }
        free(pp_permissions);
        return SECURITY_SERVER_API_ERROR_OUT_OF_MEMORY;
    } else {
        *ppp_permissions = pp_permissions;
    }

    return SECURITY_SERVER_API_SUCCESS;
}

SECURITY_SERVER_API
int security_server_perm_app_get_permissions(ss_transaction *transaction,
                                             const char *pkg_id,
                                             app_type_t app_type,
                                             char ***ppp_permissions)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_get_permissions() called");

        if (pkg_id == nullptr) {
            LogWarning("Application identifier is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (ppp_permissions == nullptr) {
            LogWarning("Permissions placeholder is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RO);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("app_id: " << pkg_id);
        LogDebug("app_type: " << app_type);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_get_permissions() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_app_get_permissions(pkg_id, app_type, ppp_permissions));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_get_permissions() failed. Error code: " << result);
            }
        } else {
            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::GET_APP_PERMISSION));
            Serialization::Serialize(send, std::string(pkg_id));
            Serialization::Serialize(send, static_cast<int>(app_type));

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_get_permissions."
                         " Error code: " << result);
            } else {
                result = deserializeAppGetPermissions(recv, ppp_permissions);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;

    });
}

SECURITY_SERVER_API
int security_server_perm_app_setup_path(ss_transaction *transaction,
                                        const char* pkg_id,
                                        const char* path,
                                        app_path_type_t app_path_type,
                                        ...)
{
    va_list ap;
    int ret;
    va_start(ap, app_path_type);
    ret = security_server_perm_app_setup_path_v(transaction, pkg_id, path, app_path_type, ap);
    va_end(ap);
    return ret;
}

SECURITY_SERVER_API
int security_server_perm_app_setup_path_v(ss_transaction *transaction,
                                         const char* pkg_id,
                                         const char* path,
                                         app_path_type_t app_path_type,
                                         va_list ap)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_setup_path_v() called");

        if (pkg_id == nullptr) {
            LogWarning("Application identifier is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (path == nullptr) {
            LogWarning("Path is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        const char* label = nullptr;
        switch(app_path_type) {
        case PERM_APP_PATH_GROUP:
        case PERM_APP_PATH_ANY_LABEL: {
            label = va_arg(ap, const char *);
            if (label == nullptr) {
                LogWarning("Label is NULL for PERM_APP_PATH_ANY_LABEL or PERM_APP_PATH_GROUP");
                return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
            }
            break;
        }
        default:
            break;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("app_id: " << pkg_id);
        LogDebug("path: " << path);
        LogDebug("app_path_type" << app_path_type);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_setup_path_v() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_app_setup_path(pkg_id, path, app_path_type, label));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_setup_path() failed. Error code: " << result);
            }
        } else {
            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::SETUP_PATH));
            Serialization::Serialize(send, std::string(pkg_id));
            Serialization::Serialize(send, std::string(path));
            Serialization::Serialize(send, static_cast<int>(app_path_type));
            if (label != nullptr)
                Serialization::Serialize(send, std::string(label));

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_setup_path_v."
                         " Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

static int deserializeAppGetPaths(SecurityServer::MessageBuffer &recv, char ***ppp_paths) {
    using namespace SecurityServer;
    std::vector<std::string> paths;
    Deserialization::Deserialize(recv, paths);

    char **pp_paths = (char **) calloc ((paths.size() + 1), sizeof (char*));
    if (pp_paths == nullptr) {
        LogError("calloc failed");
        return SECURITY_SERVER_API_ERROR_OUT_OF_MEMORY;
    }

    bool failed = false;
    size_t i;
    for (i = 0; i < paths.size(); ++i) {
        pp_paths[i] = strdup(paths[i].c_str());
        if (pp_paths[i] == nullptr) {
            LogError("Failed to copy string");
            failed = true;
            break;
        }
    }
    if (failed) {
        for(size_t j = 0; j < i; j++) {
            free(pp_paths[j]);
        }
        free(pp_paths);
        return SECURITY_SERVER_API_ERROR_OUT_OF_MEMORY;
    }

    *ppp_paths = pp_paths;
    return SECURITY_SERVER_API_SUCCESS;
}

SECURITY_SERVER_API
int security_server_perm_app_get_paths(ss_transaction *transaction,
                                       const char* pkg_id,
                                       app_path_type_t app_path_type,
                                       char*** ppp_paths)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_get_paths() called");

        if (pkg_id == nullptr) {
            LogWarning("Application identifier is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (ppp_paths == nullptr) {
            LogWarning("Permissions placeholder is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RO);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("app_id: " << pkg_id);
        LogDebug("app_path_type: " << app_path_type);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_get_paths() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_app_get_paths(pkg_id, app_path_type, ppp_paths));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_get_paths() failed. Error code: " << result);
            }
        } else {
            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::GET_PATH));
            Serialization::Serialize(send, std::string(pkg_id));
            Serialization::Serialize(send, static_cast<int>(app_path_type));

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_get_paths."
                         " Error code: " << result);
            } else {
                result = deserializeAppGetPaths(recv, ppp_paths);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_app_remove_path(ss_transaction *transaction,
                                         const char* pkg_id,
                                         const char *path)
{

    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_remove_path() called");

        if (pkg_id == nullptr) {
            LogWarning("Application identifier is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (path == nullptr) {
            LogWarning("Path is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("app_id: " << pkg_id);
        LogDebug("path: " << path);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_remove_path() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_app_remove_path(pkg_id, path));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_remove_path() failed. Error code: " << result);
            }
        } else {
            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::REMOVE_PATH));
            Serialization::Serialize(send, std::string(pkg_id));
            Serialization::Serialize(send, std::string(path));

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_remove_path."
                         " Error code: " << result);
            }
        }

        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_app_add_friend(ss_transaction *transaction,
                                        const char* pkg_id1,
                                        const char* pkg_id2)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_add_friend() called");

        if (pkg_id1 == nullptr) {
            LogWarning("Application identifier 1 is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (pkg_id2 == nullptr) {
            LogWarning("Application identifier 2 is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("pkg_id1: " << pkg_id1);
        LogDebug("pkg_id2: " << pkg_id2);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_add_friend() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_app_add_friend(pkg_id1, pkg_id2));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_add_friend() failed. Error code: " << result);
            }
        } else {
            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::ADD_FRIEND));
            Serialization::Serialize(send, std::string(pkg_id1));
            Serialization::Serialize(send, std::string(pkg_id2));

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_add_friend."
                         " Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_define_permission(ss_transaction *transaction,
                                           app_type_t app_type,
                                           const char* api_feature_name,
                                           const char* tizen_version,
                                           const char** smack_rules,
                                           bool fast)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_define_permission() called");

        if ((api_feature_name == nullptr) || (strlen(api_feature_name) == 0)) {
            LogWarning("Feature name is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        if(tizen_version == nullptr) {
            tizen_version = Configuration::TizenVersion.c_str();
        }

        if (strlen(tizen_version) == 0) {
            LogWarning("Tizen version couldn't be set");
            return SECURITY_SERVER_API_ERROR_CONFIGURATION;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }


        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("app_type: " << app_type);
        LogDebug("api_feature_name: " << api_feature_name);
        LogDebug("tizen_version: " << tizen_version);
        LogDebug("fast: " << (fast ? "true" : "false"));
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_define_permission() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_define_permission(app_type, api_feature_name,
                                                  tizen_version, smack_rules, fast));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_define_permission() failed. Error code: " << result);
            }
        } else {
            std::vector<std::string> rules;
            if (smack_rules != nullptr) {
                for (int i = 0; smack_rules[i] != nullptr; ++i) {
                    rules.push_back(smack_rules[i]);
                }
            }

            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::DEFINE_PERMISSION));
            Serialization::Serialize(send, static_cast<int>(app_type));
            Serialization::Serialize(send, std::string(api_feature_name));
            Serialization::Serialize(send, std::string(tizen_version));
            //If no rules are defined, we send empty vector
            Serialization::Serialize(send, rules);
            Serialization::Serialize(send, fast);

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_define_permission."
                         " Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_add_additional_rules(ss_transaction *transaction,
                                              const char** set_smack_rule_set)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_add_additional_rules() called");

        if (set_smack_rule_set == nullptr) {
            LogWarning("Set smack rules is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        std::vector<std::string> rules;
        for (int i = 0; set_smack_rule_set[i] != nullptr; ++i) {
            rules.push_back(set_smack_rule_set[i]);
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("Got " << rules.size() << " rules");
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_add_additional_rules() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_add_additional_rules(set_smack_rule_set));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_add_additional_rules() failed. Error code: " << result);
            }
        } else {
            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::ADDITIONAL_RULES));
            Serialization::Serialize(send, rules);

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_add_additional_rules."
                         " Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_app_set_privilege_version(ss_transaction *transaction,
                                                   const char* const s_app_label_name,
                                                   const char * const s_version)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_set_privilege_version() called");

        if (s_app_label_name == nullptr) {
            LogWarning("App label name is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        // Empty version string will be reinterpreted as default version
        std::string version;
        if (s_version != nullptr) {
            version = s_version;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("s_app_label_name : " << s_app_label_name);
        LogDebug("s_version : " << version);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_set_privilege_version() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_app_set_privilege_version(s_app_label_name, version.c_str()));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_set_privilege_version() failed. Error code: " << result);
            }
        } else {
            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::SET_PRIV_VERSION));
            Serialization::Serialize(send, std::string(s_app_label_name));
            Serialization::Serialize(send, version);

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_set_privilege_version."
                         " Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_app_get_privilege_version(ss_transaction *transaction,
                                                   const char* const s_app_label_name,
                                                   char **p_version)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_get_privilege_version() called");

        if (s_app_label_name == nullptr) {
            LogWarning("App label name is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (p_version == nullptr) {
            LogWarning("Version placeholder is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RO);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("s_app_label_name : " << s_app_label_name);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_get_privilege_version() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_app_get_privilege_version(s_app_label_name, p_version));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_get_privilege_version() failed. Error code: " << result);
            }
        } else {
            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::GET_PRIV_VERSION));
            Serialization::Serialize(send, std::string(s_app_label_name));

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_get_privilege_version."
                         " Error code: " << result);
            } else {
                std::string version;
                Deserialization::Deserialize(recv, version);

                *p_version = strdup(version.c_str());
                if (*p_version == nullptr) {
                    LogError("strdup failed while copying version");
                    result = SECURITY_SERVER_API_ERROR_OUT_OF_MEMORY;
                }
            }
        }

        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_app_enable_blacklist_permissions(ss_transaction *transaction,
                                                          const char* const s_app_label_name,
                                                          app_type_t perm_type,
                                                          const char** pp_perm_list)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_enable_blacklist_permissions() called");

        if (s_app_label_name == nullptr) {
            LogWarning("App label is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (pp_perm_list == nullptr || pp_perm_list[0] == nullptr) {
            LogWarning("Perm_list is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("s_app_label_name: " << s_app_label_name);
        LogDebug("perm_type: " << (int)perm_type);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_enable_blacklist_permissions() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_app_enable_blacklist_permissions(s_app_label_name, perm_type,
                                                                 pp_perm_list));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_enable_blacklist_permissions() failed. Error code: " << result);
            }
        } else {
            //put all strings in STL vector
            std::vector<std::string> permissions;
            for (int i = 0; pp_perm_list[i] != nullptr; i++) {
                LogDebug("perm_list[" << i << "]: " << pp_perm_list[i]);
                permissions.push_back(std::string(pp_perm_list[i]));
            }

            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::ENABLE_BLACKLIST));
            Serialization::Serialize(send, std::string(s_app_label_name));
            Serialization::Serialize(send, static_cast<int>(perm_type));
            Serialization::Serialize(send, permissions);

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_enable_blacklist_permissions."
                         " Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_app_disable_blacklist_permissions(ss_transaction *transaction,
                                                           const char* const s_app_label_name,
                                                           app_type_t perm_type,
                                                           const char** pp_perm_list)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_disable_blacklist_permissions() called");

        if (s_app_label_name == nullptr) {
            LogWarning("App label is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (pp_perm_list == nullptr || pp_perm_list[0] == nullptr) {
            LogWarning("Perm_list is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("s_app_label_name: " << s_app_label_name);
        LogDebug("perm_type: " << (int)perm_type);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_disable_blacklist_permissions() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_app_disable_blacklist_permissions(s_app_label_name, perm_type,
                                                                  pp_perm_list));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_disable_blacklist_permissions() failed. Error code: " << result);
            }
        } else {
            //put all strings in STL vector
            std::vector<std::string> permissions_list;
            for (int i = 0; pp_perm_list[i] != nullptr; i++) {
                LogDebug("perm_list[" << i << "]: " << pp_perm_list[i]);
                permissions_list.push_back(std::string(pp_perm_list[i]));
            }

            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::DISABLE_BLACKLIST));
            Serialization::Serialize(send, std::string(s_app_label_name));
            Serialization::Serialize(send, static_cast<int>(perm_type));
            Serialization::Serialize(send, permissions_list);

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_disable_blacklist_permissions."
                         " Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

static int deserializeAppGetBlacklistStatuses(SecurityServer::MessageBuffer &recv,
                                              perm_blacklist_status_t **pp_perm_list,
                                              size_t *p_perm_number) {
    using namespace SecurityServer;
    int permissions_cnt;
    Deserialization::Deserialize(recv, permissions_cnt);
    if (permissions_cnt == 0) {
        *pp_perm_list = nullptr;
        *p_perm_number = 0;
        return SECURITY_SERVER_API_SUCCESS;
    }
    int copied_cnt = 0;
    auto free_list = std::bind(security_server_perm_free_blacklist_statuses, std::placeholders::_1,
                               std::ref(copied_cnt));
    std::unique_ptr<perm_blacklist_status_t, decltype (free_list)> permBlacklistStatusArr(
            static_cast<perm_blacklist_status_t*>(malloc(permissions_cnt * sizeof(perm_blacklist_status_t))),
            free_list);

    if (!permBlacklistStatusArr)
        throw std::bad_alloc();
    for (int i = 0; i < permissions_cnt; ++i) {
        Deserialization::Deserialize(recv, permBlacklistStatusArr.get()[i]);
    }

    *pp_perm_list = permBlacklistStatusArr.release();
    *p_perm_number = permissions_cnt;
    return SECURITY_SERVER_API_SUCCESS;
}

SECURITY_SERVER_API
int security_server_perm_app_get_blacklist_statuses(ss_transaction *transaction,
                                                    const char* const s_app_label_name,
                                                    perm_blacklist_status_t** pp_perm_list,
                                                    size_t* p_perm_number)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_app_get_blacklist_statuses() called");

        if (s_app_label_name == nullptr) {
            LogWarning("Application label is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (pp_perm_list == nullptr) {
            LogWarning("Permissions placeholder is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (p_perm_number == nullptr) {
            LogWarning("Permissions number placeholder is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RO);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("s_app_label_name: " << s_app_label_name);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogDebug("security_server_perm_app_get_blacklist_statuses() in offline mode");
            result = privilegeToSecurityServerError(
                        ss_perm_app_get_blacklist_statuses(s_app_label_name, pp_perm_list,
                                                           p_perm_number));
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("ss_perm_app_get_blacklist_statuses() failed. Error code: " << result);
            }
        } else {
            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::GET_BLACKLIST));
            Serialization::Serialize(send, std::string(s_app_label_name));

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_app_get_blacklist_statuses."
                         " Error code: " << result);
            } else {
                result = deserializeAppGetBlacklistStatuses(recv, pp_perm_list, p_perm_number);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {

            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
void security_server_perm_free_blacklist_statuses(perm_blacklist_status_t* p_perm_list,
                                                  size_t i_perm_number)
{
    if (p_perm_list == nullptr)
        return;
    for (size_t i = 0; i < i_perm_number; i++)
        free(p_perm_list[i].permission_name);
    free(p_perm_list);
}

SECURITY_SERVER_API
int security_server_perm_db_configuration_refresh(const char *const dir,
                                                  int clear_not_found_permissions)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_db_configuration_refresh() called");
        if (!checkCaller()) {
            LogError("security_server_perm_db_configuration_refresh is allowed only to root");
            return SECURITY_SERVER_API_ERROR_OPERATION_NOT_PERMITTED;
        }

        LogDebug("dir : " << dir);
        LogDebug("clear_not_found_permissions : "
                    << (clear_not_found_permissions == 1 ? "true" : "false"));
        return privilegeToSecurityServerError(
                ss_perm_db_configuration_refresh(dir, clear_not_found_permissions));
    });
}

SECURITY_SERVER_API
int security_server_perm_apply_sharing(ss_transaction *transaction,
                                       const char **path_list,
                                       const char *owner_pkg_id,
                                       const char *receiver_pkg_id)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_apply_sharing() called");
        if (path_list == nullptr) {
            LogWarning("Path list is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (owner_pkg_id == nullptr) {
            LogWarning("Owner pkg id is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (receiver_pkg_id == nullptr) {
            LogWarning("Receiver pkg id is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("owner_pkg_id: " << owner_pkg_id);
        LogDebug("receiver_pkg_id: " << receiver_pkg_id);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogError("security_server_perm_apply_sharing() in not available in offline mode");
            return SECURITY_SERVER_API_ERROR_SOCKET;
        } else {
            std::vector<std::string> paths;
            for (int i = 0; path_list[i]; i++)
                paths.push_back(path_list[i]);

            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::APPLY_SHARING));
            Serialization::Serialize(send, paths);
            Serialization::Serialize(send, std::string(owner_pkg_id));
            Serialization::Serialize(send, std::string(receiver_pkg_id));

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_apply_sharing."
                         " Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {
            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

SECURITY_SERVER_API
int security_server_perm_drop_sharing(ss_transaction *transaction,
                                      const char **path_list,
                                      const char *owner_pkg_id,
                                      const char *receiver_pkg_id)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_perm_drop_sharing() called");
        if (path_list == nullptr) {
            LogWarning("Path list is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (owner_pkg_id == nullptr) {
            LogWarning("Owner pkg id is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (receiver_pkg_id == nullptr) {
            LogWarning("Receiver pkg id is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        ss_transaction *current_transaction = NULL;
        TransactionPtr current_transaction_ptr;
        if (transaction == nullptr) {
            LogDebug("User transaction is NULL");
            int ret = createTransaction(current_transaction_ptr, TransactionType::RW);
            if (ret != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't create local transaction");
                return ret;
            }
            current_transaction = current_transaction_ptr.get();
        } else {
            current_transaction = transaction;
        }

        LogDebug("transaction : " << (transaction ? "user" : "local"));
        LogDebug("owner_pkg_id: " << owner_pkg_id);
        LogDebug("receiver_pkg_id: " << receiver_pkg_id);
        LogDebug("mode: " << (current_transaction->offlineMode ? "offline" : "online"));

        int result;
        if (current_transaction->offlineMode) {
            LogError("security_server_perm_drop_sharing() in not available in offline mode");
            return SECURITY_SERVER_API_ERROR_SOCKET;
        } else {
            std::vector<std::string> paths;
            for (int i = 0; path_list[i]; i++)
                paths.push_back(path_list[i]);

            //put data into buffer
            MessageBuffer send, recv;
            Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::DROP_SHARING));
            Serialization::Serialize(send, paths);
            Serialization::Serialize(send, std::string(owner_pkg_id));
            Serialization::Serialize(send, std::string(receiver_pkg_id));

            //send buffer to server
            result = sendToServerWithFd(current_transaction->sock.Get(), send.Pop(), recv);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << result);
                return result;
            }

            //receive response from server
            Deserialization::Deserialize(recv, result);
            if (result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Error processing security_server_perm_drop_sharing."
                         " Error code: " << result);
            }
        }
        int commit_result = SECURITY_SERVER_API_SUCCESS;
        if (transaction == nullptr) {
            commit_result = commitTransaction(current_transaction_ptr);
            if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
            }
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}

/*-----------------------------------------------------------------------------------------------*/

SECURITY_SERVER_API
int security_server_app_enable_permissions(const char *app_id, app_type_t app_type, const char **perm_list, int persistent)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_app_enable_permissions() called");

        if ((nullptr == app_id) || (strlen(app_id) == 0)) {
            LogWarning("App_id is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if ((nullptr == perm_list) || perm_list[0] == nullptr) {
            LogWarning("Perm_list is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        TransactionPtr transaction;
        int ret = createTransaction(transaction, TransactionType::RW, true,
                                    SERVICE_SOCKET_APP_PERMISSIONS);
        if (ret != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Couldn't create local transaction");
            return ret;
        }

        LogDebug("app_type: " << (int)app_type);
        LogDebug("persistent: " << persistent);
        LogDebug("app_id: " << app_id);

        //put all strings in STL vector
        std::vector<std::string> permissions_list;
        for (int i = 0; perm_list[i] != nullptr; i++) {
            LogDebug("perm_list[" << i << "]: " << perm_list[i]);
            permissions_list.push_back(std::string(perm_list[i]));
        }

        //put data into buffer
        MessageBuffer send, recv;
        Serialization::Serialize(send, (int)AppPermissionsAction::ENABLE);   //works as a MSG_ID
        Serialization::Serialize(send, persistent);
        Serialization::Serialize(send, (int)app_type);
        Serialization::Serialize(send, std::string(app_id));
        Serialization::Serialize(send, permissions_list);

        //send buffer to server
        int result = sendToServerWithFd(transaction->sock.Get(), send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << result);
            return result;
        }
        //receive response from server
        Deserialization::Deserialize(recv, result);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            LogError("security_server_app_enable_permissions failed.");
        }
        int commit_result = commitTransaction(transaction);
        if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}


SECURITY_SERVER_API
int security_server_app_disable_permissions(const char *app_id, app_type_t app_type, const char **perm_list)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_app_disable_permissions() called");

        if ((nullptr == app_id) || (strlen(app_id) == 0)) {
            LogWarning("App_id is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if ((nullptr == perm_list) || perm_list[0] == nullptr) {
            LogWarning("Perm_list is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        TransactionPtr transaction;
        int ret = createTransaction(transaction, TransactionType::RW, true,
                                    SERVICE_SOCKET_APP_PERMISSIONS);
        if (ret != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Couldn't create local transaction");
            return ret;
        }

        LogDebug("app_type: " << (int)app_type);
        LogDebug("app_id: " << app_id);

        //put all strings in STL vector
        std::vector<std::string> permissions_list;
        for (int i = 0; perm_list[i] != nullptr; i++) {
            LogDebug("perm_list[" << i << "]: " << perm_list[i]);
            permissions_list.push_back(std::string(perm_list[i]));
        }

        //put data into buffer
        MessageBuffer send, recv;
        Serialization::Serialize(send, (int)AppPermissionsAction::DISABLE);   //works as a MSG_ID
        Serialization::Serialize(send, (int)app_type);
        Serialization::Serialize(send, std::string(app_id));
        Serialization::Serialize(send, permissions_list);

        //send buffer to server
        int result = sendToServerWithFd(transaction->sock.Get(), send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << result);
            return result;
        }

        //receive response from server
        Deserialization::Deserialize(recv, result);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            LogError("security_server_app_disable_permissions failed on server side.");
        }
        int commit_result = commitTransaction(transaction);
        if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
        }

        return result != SECURITY_SERVER_API_SUCCESS ? result : commit_result;
    });
}


SECURITY_SERVER_API
int security_server_app_has_privilege(const char *app_id,
                                      app_type_t app_type,
                                      const char *privilege_name,
                                      int *result)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_app_has_privilege() called");

        if ((nullptr == app_id) || (strlen(app_id) == 0)) {
            LogWarning("app_id is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if ((nullptr == privilege_name) || (strlen(privilege_name) == 0)) {
            LogWarning("privilege_name is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (nullptr == result) {
            LogWarning("result is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        TransactionPtr transaction;
        int ret = createTransaction(transaction, TransactionType::RO, true,
                                    SERVICE_SOCKET_APP_PRIVILEGE_BY_NAME);
        if (ret != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Couldn't create local transaction");
            return ret;
        }

        LogDebug("app_id: " << app_id);
        LogDebug("app_type: " << static_cast<int>(app_type));
        LogDebug("privilege_name: " << privilege_name);

        //put data into buffer
        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::CHECK_GIVEN_APP));
        Serialization::Serialize(send, std::string(app_id));
        Serialization::Serialize(send, static_cast<int>(app_type));
        Serialization::Serialize(send, std::string(privilege_name));

        //send buffer to server
        int apiResult = sendToServerWithFd(transaction->sock.Get(), send.Pop(), recv);
        if (apiResult != SECURITY_SERVER_API_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << apiResult);
            return apiResult;
        }

        //receive response from server
        Deserialization::Deserialize(recv, apiResult);
        Deserialization::Deserialize(recv, *result);
        if (apiResult != SECURITY_SERVER_API_SUCCESS) {
            LogError("security_server_app_has_privilege failed on server side.");
        }
        int commit_result = commitTransaction(transaction);
        if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
        }

        return apiResult != SECURITY_SERVER_API_SUCCESS ? apiResult : commit_result;
    });

    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}


SECURITY_SERVER_API
int security_server_app_caller_has_privilege(app_type_t app_type,
                                             const char *privilege_name,
                                             int *result)
{
    using namespace SecurityServer;

    return try_catch([&] {
        LogDebug("security_server_app_caller_has_privilege() called");

        if ((nullptr == privilege_name) || (strlen(privilege_name) == 0)) {
            LogWarning("privilege_name is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (nullptr == result) {
            LogWarning("result is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        TransactionPtr transaction;
        int ret = createTransaction(transaction, TransactionType::RO, true,
                                    SERVICE_SOCKET_APP_PRIVILEGE_BY_NAME);
        if (ret != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Couldn't create local transaction");
            return ret;
        }

        LogDebug("app_type: " << static_cast<int>(app_type));
        LogDebug("privilege_name: " << privilege_name);

        //put data into buffer
        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(AppPermissionsAction::CHECK_CALLER_APP));
        Serialization::Serialize(send, static_cast<int>(app_type));
        Serialization::Serialize(send, std::string(privilege_name));

        //send buffer to server
        int apiResult = sendToServerWithFd(transaction->sock.Get(), send.Pop(), recv);
        if (apiResult != SECURITY_SERVER_API_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << apiResult);
            return apiResult;
        }

        //receive response from server
        Deserialization::Deserialize(recv, apiResult);
        Deserialization::Deserialize(recv, *result);
        if (apiResult != SECURITY_SERVER_API_SUCCESS) {
            LogError("security_server_app_caller_has_privilege had failed on server side.");
        }
        int commit_result = commitTransaction(transaction);
        if (commit_result != SECURITY_SERVER_API_SUCCESS) {
                LogError("Couldn't commit local transaction");
        }

        return apiResult != SECURITY_SERVER_API_SUCCESS ? apiResult : commit_result;
    });

    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}
