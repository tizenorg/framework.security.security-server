/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 * @file        plugin-handler.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementation of PluginHandler class.
 */
#ifndef _SECURITY_SERVER_PASSWORD_PLUGIN_HANDLER_H_
#define _SECURITY_SERVER_PASSWORD_PLUGIN_HANDLER_H_

#include <string>

#include <sys/types.h>

#include <security-server-plugin-api.h>

namespace SecurityServer {

const static uid_t APP_USER = 5000;

class PluginHandler {
public:
    PluginHandler();
    PluginHandler(const PluginHandler&) = delete;
    PluginHandler& operator=(const PluginHandler&) = delete;
    bool fail() const;

    int changeUserPassword(uid_t user, const std::string &oldPass, const std::string &newPass);
    int login(uid_t user, const std::string &password);
    int logout(uid_t user);
    int resetUserPassword(uid_t user, const std::string &newPass);
    int removeUserData(uid_t user);

    virtual ~PluginHandler();
private:
    void *m_libHandler;
    DestroyPasswordPlugin_t m_destroy;
    PasswordPlugin *m_plugin;
    bool m_fail;
};

} // namespace SecurityServer

#endif // _SECURITY_SERVER_PASSWORD_PLUGIN_HANDLER_H_

