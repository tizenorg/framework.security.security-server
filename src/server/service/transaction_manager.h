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
 * @file        transaction-manager.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Declaration of TransactionManager class and implementation of Transaction class
 */

#ifndef _SECURITY_SERVER_TRANSACTION_MANAGER_H_
#define _SECURITY_SERVER_TRANSACTION_MANAGER_H_

#include <generic-socket-manager.h>

#include <list>
#include <map>
#include <vector>

namespace SecurityServer {

class TransactionManager{
public:
    enum class Action {
        BEGIN_RO,
        BEGIN_RW,
        ACTION_RO,
        ACTION_RW,
        END
    };

    class Transaction {
    public:
        enum class Type {
            RW,
            RO
        };
        enum class Status {
            BEGIN,
            END
        };

        Transaction() : m_status(Status::BEGIN) {}

        void begin(const ConnectionID &_conn) {
            m_conn = _conn;
            m_status = Status::BEGIN;
        }
        void finish() {
            m_status = Status::END;
        }
        bool isFinished() const {
            return m_status == Status::END;
        }
        ConnectionID getConnectionID() const {
            return m_conn;
        }
    private:
        ConnectionID m_conn;
        Status m_status;
    };

    typedef std::vector<ConnectionID> ConnectionIDVector;

    bool checkClientAction(Action action, const ConnectionID &conn) const;

    ConnectionIDVector lockDb(const ConnectionID &conn, Transaction::Type type);
    void unlockDb(const ConnectionID &conn);
    ConnectionIDVector updateCurrentTransaction();
    void finishClientTransaction(const ConnectionID &conn);
    bool isClientTransactionFinished(const ConnectionID &conn) const;
    bool isDbLocked() const;
    bool isDbLocked(Transaction::Type type) const;
    bool isReadOnlyClient(const ConnectionID &conn) const;
    bool isReadWriteClient(const ConnectionID &conn) const;
    bool isActiveClient(const ConnectionID &conn) const;

    ConnectionIDVector updateRW();
    ConnectionIDVector updateRO();

private:
    std::map<int, Transaction> m_activeTransactionMap;
    Transaction::Type m_dbLockType;
    std::list<ConnectionID> m_pendingRWClientList;
    std::map<int, ConnectionID> m_pendingROClientMap;
};

} //namespace SecurityServer

#endif /* _SECURITY_SERVER_TRANSACTION_MANAGER_H_ */
