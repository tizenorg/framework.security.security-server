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
 * @file        plugin-handler.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementation of PluginHandler class.
 */
#include <dlfcn.h>

#include <dpl/log/log.h>
#include <plugin-handler.h>

namespace SecurityServer {

namespace {

const char * const PLUGIN_PATH = "/usr/lib/libsecurity-server-plugin.so";

} // namespace anonymous

PluginHandler::PluginHandler()
  : m_libHandler(NULL)
  , m_destroy(NULL)
  , m_plugin(NULL)
  , m_fail(true)
{
    m_libHandler = dlopen(PLUGIN_PATH, RTLD_NOW);
    if (!m_libHandler) {
        LogError("Plugin library has not been found/opened: " << dlerror());
        return;
    }

    CreatePasswordPlugin_t createFun =
            reinterpret_cast<CreatePasswordPlugin_t>(dlsym(m_libHandler, "create"));
    if (!createFun) {
        LogError("Symbol create has not been found: " << dlerror());
        return;
    }

    m_destroy = reinterpret_cast<DestroyPasswordPlugin_t>(dlsym(m_libHandler, "destroy"));

    if (!m_destroy) {
        LogError("Symbol destroy has not been found: " << dlerror());
        return;
    }

    m_plugin = createFun();

    if (!m_plugin) {
        LogError("Plugin creation failed...");
        return;
    }

    m_fail = false;
}

bool PluginHandler::fail() const {
    return m_fail;
}

int PluginHandler::changeUserPassword(
    uid_t user,
    const std::string &oldPass,
    const std::string &newPass)
{
    if (m_plugin)
        return m_plugin->changeUserPassword(user, oldPass, newPass);
    return SECURITY_SERVER_PLUGIN_SUCCESS;
}

int PluginHandler::login(uid_t user, const std::string &password) {
    if (m_plugin)
        return m_plugin->login(user, password);
    return SECURITY_SERVER_PLUGIN_SUCCESS;
}

int PluginHandler::logout(uid_t user) {
    if (m_plugin)
        return m_plugin->logout(user);
    return SECURITY_SERVER_PLUGIN_SUCCESS;
}

int PluginHandler::resetUserPassword(uid_t user, const std::string &newPass) {
    if (m_plugin)
        return m_plugin->resetUserPassword(user, newPass);
    return SECURITY_SERVER_PLUGIN_SUCCESS;
}

int PluginHandler::removeUserData(uid_t user) {
    if (m_plugin)
        return m_plugin->removeUserData(user);
    return SECURITY_SERVER_PLUGIN_SUCCESS;
}

PluginHandler::~PluginHandler() {
    if (m_destroy && m_plugin) {
        m_destroy(m_plugin);
    }

    if (m_libHandler) {
        dlclose(m_libHandler);
    }
}

} // namespace SecurityServer

