/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        transaction-manager.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Implementation of TransactionManager class
 */

#include <generic-socket-manager.h>
#include <transaction_manager.h>

#include <algorithm>
#include <utility>
#include <list>
#include <map>

#include <dpl/log/log.h>


namespace SecurityServer {

    bool TransactionManager::isDbLocked() const {
        return !m_activeTransactionMap.empty();
    }
    bool TransactionManager::isDbLocked(TransactionManager::Transaction::Type type) const {
        return !m_activeTransactionMap.empty() && m_dbLockType == type;

    }
    bool TransactionManager::isReadOnlyClient(const ConnectionID &conn) const {
        if (m_dbLockType == Transaction::Type::RO)
            if (m_activeTransactionMap.find(conn.counter) != m_activeTransactionMap.end())
                return true;

        return m_pendingROClientMap.find(conn.counter) != m_pendingROClientMap.end();

    }
    bool TransactionManager::isReadWriteClient(const ConnectionID &conn) const {
        if (m_dbLockType == Transaction::Type::RW)
            if (m_activeTransactionMap.find(conn.counter) != m_activeTransactionMap.end())
                return true;

        auto it = std::find(m_pendingRWClientList.begin(), m_pendingRWClientList.end(), conn);
        return it != m_pendingRWClientList.end();
    }
    bool TransactionManager::isActiveClient(const ConnectionID &conn) const {
        return m_activeTransactionMap.find(conn.counter) != m_activeTransactionMap.end();
    }

    TransactionManager::ConnectionIDVector TransactionManager::updateRW() {
        ConnectionIDVector clientsToNotify;
        if (m_pendingRWClientList.empty())
            return clientsToNotify;
        auto first_client = m_pendingRWClientList.front();
        m_pendingRWClientList.pop_front();
        m_activeTransactionMap[first_client.counter].begin(first_client);
        clientsToNotify.push_back(first_client);
        m_dbLockType = Transaction::Type::RW;
        return clientsToNotify;
    }
    TransactionManager::ConnectionIDVector TransactionManager::updateRO() {
        ConnectionIDVector clientsToNotify;
        if (m_pendingROClientMap.empty())
            return clientsToNotify;
        std::transform(m_pendingROClientMap.begin(),
                       m_pendingROClientMap.end(),
                       std::inserter(m_activeTransactionMap, m_activeTransactionMap.end()),
                       [&clientsToNotify] (const std::pair<int, ConnectionID> &element) {
                            Transaction tr;
                            tr.begin(element.second);
                            clientsToNotify.push_back(element.second);
                            return std::make_pair(element.first, tr);
                       }
        );
        m_pendingROClientMap.clear();
        m_dbLockType = Transaction::Type::RO;
        return clientsToNotify;
    }
    TransactionManager::ConnectionIDVector TransactionManager::updateCurrentTransaction() {
        ConnectionIDVector clientsToNotify;
        if (isDbLocked())
            return clientsToNotify;

        //DB was in RO mode, allow RW clients first
        if (m_dbLockType == Transaction::Type::RO) {
            clientsToNotify = updateRW();
            if (clientsToNotify.empty())
                return updateRO();
        } else {
            clientsToNotify = updateRO();
            if (clientsToNotify.empty())
                return updateRW();
        }

        return clientsToNotify;
    }

    std::vector<ConnectionID> TransactionManager::lockDb(const ConnectionID &conn,
                                                         Transaction::Type type)
    {
        if (type == Transaction::Type::RW) {
            m_pendingRWClientList.push_back(conn);
        } else {
            m_pendingROClientMap[conn.counter] = conn;
        }
        return updateCurrentTransaction();
    }

    void TransactionManager::unlockDb(const ConnectionID &conn) {
        if (!isDbLocked())
            return;

        if (!m_activeTransactionMap.erase(conn.counter)) {
            return;
        }

        if (!m_pendingROClientMap.erase(conn.counter)) {
            return;
        }

        // Removing pending RW client
        auto itRW = std::find(m_pendingRWClientList.begin(), m_pendingRWClientList.end(),
                              conn);
        if (itRW != m_pendingRWClientList.end())
            m_pendingRWClientList.erase(itRW);
    }

    bool TransactionManager::checkClientAction(TransactionManager::Action action,
                                               const ConnectionID &conn) const
    {
        if (isClientTransactionFinished(conn)){
            LogError("Client tries to make action after transaction was finished");
            return false;
        }
        switch(action) {
        case Action::BEGIN_RW:
            if (isReadOnlyClient(conn)) {
                LogError("Client already started RO transaction");
                return false;
            }
            if (isReadWriteClient(conn)) {
                LogError("Client tries to begin another RW transaction");
                return false;
            }
            break;
        case Action::BEGIN_RO:
            if (isReadWriteClient(conn)) {
                LogError("Client already started RW transaction");
                return false;
            }
            if (isReadOnlyClient(conn)) {
                LogError("Client tries to begin another RO transaction");
                return false;
            }
            break;
        case Action::ACTION_RW:
            if (isDbLocked(Transaction::Type::RO)) {
                LogError("Processing RO transactions, no RW actions allowed");
                return false;
            }
            if (!isActiveClient(conn)) {
                LogError("Client does not hold current transaction");
                return false;
            }
            break;
        case Action::ACTION_RO:
            if (!isActiveClient(conn)) {
                LogError("Client does not hold current transaction");
                return false;
            }
            break;
        case Action::END:
            if (!isReadOnlyClient(conn) && !isReadWriteClient(conn)) {
                LogError("Client does not hold any transaction");
                return false;
            }
        }
        return true;
    }

    void TransactionManager::finishClientTransaction(const ConnectionID &conn) {
        m_activeTransactionMap[conn.counter].finish();
    }

    bool TransactionManager::isClientTransactionFinished(const ConnectionID &conn) const {
        auto it = m_activeTransactionMap.find(conn.counter);
        if (it == m_activeTransactionMap.end())
            return false;
        return it->second.isFinished();
    }

}

