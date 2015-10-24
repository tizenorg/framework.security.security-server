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
 * @file        password-manager.h
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @version     1.0
 * @brief       Implementation of password management functions
 */

#ifndef _PASSWORDMANAGER_H_
#define _PASSWORDMANAGER_H_

#include <string>
#include <map>

#include <password-file.h>
#include <plugin-handler.h>

namespace SecurityServer
{
    class PasswordManager
    {
    public:
        typedef std::map<std::string, PasswordFile> PasswordFileMap;

        //checking functions
        int isPwdValid(const std::string &zone, unsigned int &currentAttempt,
                       unsigned int &maxAttempt, unsigned int &expirationTime);
        int isPwdReused(const std::string &zone, const std::string &pwd, bool &isReused);
        int checkPassword(const std::string &zone, const std::string& challenge,
                          unsigned int &currentAttempt, unsigned int &maxAttempt,
                          unsigned int &expTime);
        //no const in checkPassword, attempts are updated

        //setting functions
        int setPassword(const std::string &zone, const std::string &currentPassword,
                        const std::string &newPassword, const unsigned int receivedAttempts,
                        const unsigned int receivedDays, PluginHandler &plugin);
        int setPasswordValidity(const std::string &zone, const unsigned int receivedDays);
        int resetPassword(const std::string &zone, const std::string &newPassword,
                          const unsigned int receivedAttempts, const unsigned int receivedDays,
                          PluginHandler &plugin);
        int setPasswordHistory(const std::string &zone, const unsigned int history);
        int setPasswordMaxChallenge(const std::string &zone, const unsigned int maxChallenge);

    private:
        //managing functions
        void addPassword(const std::string &zone);
        void removePassword(const std::string &zone);
        void existPassword(const std::string &zone);

        PasswordFileMap m_pwdFile;
    };
} //namespace SecurityServer

#endif
