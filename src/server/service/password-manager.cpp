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
 * @file        password-manager.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @version     1.0
 * @brief       Implementation of password management functions
 */

#include <password-manager.h>

#include <iostream>
#include <iterator>
#include <algorithm>

#include <limits.h>

#include <dpl/log/log.h>

#include <protocols.h>

#include <security-server-error.h>

namespace {
    bool calculateExpiredTime(unsigned int receivedDays, time_t &validSecs)
    {
        validSecs = SecurityServer::PASSWORD_INFINITE_EXPIRATION_TIME;

        //when receivedDays means infinite expiration, return default validSecs value.
        if(receivedDays == SecurityServer::PASSWORD_INFINITE_EXPIRATION_DAYS)
            return true;

        time_t curTime = time(NULL);

        if (receivedDays > ((UINT_MAX - curTime) / 86400)) {
            LogError("Incorrect input param.");
            return false;
        } else {
            validSecs = (curTime + (receivedDays * 86400));
            return true;
        }
    }
} //namespace

namespace SecurityServer
{
    void PasswordManager::addPassword(const std::string &zone)
    {
        m_pwdFile.insert(PasswordFileMap::value_type(zone, PasswordFile(zone)));
    }

    void PasswordManager::removePassword(const std::string &zone)
    {
        m_pwdFile.erase(zone);
    }

    void PasswordManager::existPassword(const std::string &zone)
    {
        PasswordFileMap::iterator itPwd = m_pwdFile.find(zone);

        if (itPwd != m_pwdFile.end()) {
            if (!itPwd->second.checkDataDir())
                removePassword(zone);
            else
                return;
        }
        addPassword(zone);
        return;
    }

    int PasswordManager::isPwdValid(const std::string &zone, unsigned int &currentAttempt,
                                    unsigned int &maxAttempt, unsigned int &expirationTime)
    {
        existPassword(zone);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(zone);

        if (!itPwd->second.isPasswordActive()) {
            LogError("Current password not active.");
            return SECURITY_SERVER_API_ERROR_NO_PASSWORD;
        } else {
            currentAttempt = itPwd->second.getAttempt();
            maxAttempt = itPwd->second.getMaxAttempt();
            expirationTime = itPwd->second.getExpireTimeLeft();

            return SECURITY_SERVER_API_ERROR_PASSWORD_EXIST;
        }

        return SECURITY_SERVER_API_SUCCESS;
    }

    int PasswordManager::isPwdReused(const std::string &zone,
                                     const std::string &pwd,
                                     bool &isReused)
    {
        existPassword(zone);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(zone);

        isReused = false;

        // check history, however only if history is active and password is not empty
        if (itPwd->second.isHistoryActive() && !pwd.empty()) {
            isReused = itPwd->second.isPasswordReused(pwd);
        }

        return SECURITY_SERVER_API_SUCCESS;
    }

    int PasswordManager::checkPassword(const std::string &zone, const std::string &challenge,
                                       unsigned int &currentAttempt, unsigned int &maxAttempt,
                                       unsigned int &expirationTime)
    {
        LogSecureDebug("Inside checkPassword function.");

        existPassword(zone);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(zone);

        if (itPwd->second.isIgnorePeriod()) {
            LogError("Retry timeout occurred.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_RETRY_TIMER;
        }

        if (!itPwd->second.isPasswordActive() && !challenge.empty()) {
            LogError("Password not active.");
            return SECURITY_SERVER_API_ERROR_NO_PASSWORD;
        }

        itPwd->second.incrementAttempt();
        itPwd->second.writeAttemptToFile();

        currentAttempt = itPwd->second.getAttempt();
        maxAttempt = itPwd->second.getMaxAttempt();
        expirationTime = itPwd->second.getExpireTimeLeft();

        if (itPwd->second.checkIfAttemptsExceeded()) {
            LogError("Too many tries.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED;
        }

        if (!itPwd->second.checkPassword(challenge)) {
            LogError("Wrong password.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH;
        }

        // Password maches and attempt number is fine - time to reset counter.
        itPwd->second.resetAttempt();
        itPwd->second.writeAttemptToFile();

        // Password is too old. You must change it before login.
        if (itPwd->second.checkExpiration()) {
            LogError("Password expired.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_EXPIRED;
        }

        return SECURITY_SERVER_API_SUCCESS;
    }

    int PasswordManager::setPassword(const std::string &zone,
                                     const std::string &currentPassword,
                                     const std::string &newPassword,
                                     const unsigned int receivedAttempts,
                                     const unsigned int receivedDays,
                                     PluginHandler &plugin)
    {
        LogSecureDebug("Zone = " << zone << ", curpwd = " << currentPassword <<
                       ", newpwd = " << newPassword << ", recatt = " << receivedAttempts <<
                       ", recdays = " << receivedDays);

        time_t valid_secs = 0;

        existPassword(zone);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(zone);

        if (itPwd->second.isIgnorePeriod()) {
            LogError("Retry timeout occured.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_RETRY_TIMER;
        }

        //check if passwords are correct
        if (currentPassword.size() > MAX_PASSWORD_LEN) {
            LogError("Current password length failed.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        if (newPassword.size() > MAX_PASSWORD_LEN) {
            LogError("New password length failed.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        // You remove password and set up receivedAttempts or receivedDays
        if (newPassword.empty() && (receivedAttempts != 0 || receivedDays != 0)) {
            LogError("Attempts or receivedDays is not equal 0");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        // check delivered currentPassword
        // when m_passwordActive flag is false, current password should be empty
        if (!currentPassword.empty() && !itPwd->second.isPasswordActive()) {
            LogError("Password not active.");
            return SECURITY_SERVER_API_ERROR_NO_PASSWORD;
        }

        //increment attempt count before checking it against max attempt count
        itPwd->second.incrementAttempt();
        itPwd->second.writeAttemptToFile();

        if (itPwd->second.checkIfAttemptsExceeded()) {
            LogError("Too many tries.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED;
        }

        if (!itPwd->second.checkPassword(currentPassword)) {
            LogError("Wrong password.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH;
        }

        //here we are sure that user knows current password - we can reset attempt counter
        itPwd->second.resetAttempt();
        itPwd->second.writeAttemptToFile();

        // check history, however only if history is active and new password is not empty
        if (itPwd->second.isHistoryActive() && !newPassword.empty()) {
            if (itPwd->second.isPasswordReused(newPassword)) {
                LogError("Password reused.");
                return SECURITY_SERVER_API_ERROR_PASSWORD_REUSED;
            }
        }

        if (!calculateExpiredTime(receivedDays, valid_secs)) {
            LogError("Received expiration time incorrect.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        if (SECURITY_SERVER_PLUGIN_SUCCESS != plugin.changeUserPassword(zone, APP_USER, currentPassword, newPassword))
        {
            LogError("Plugin reject password change!");
            return SECURITY_SERVER_API_ERROR_PASSWORD_PLUGIN;
        }

        //setting password
        itPwd->second.setPassword(newPassword);
        itPwd->second.setMaxAttempt(receivedAttempts);
        itPwd->second.setExpireTime(valid_secs);
        itPwd->second.writeMemoryToFile();

        // unlockUserKey is treated as confirmation of new password by CKM (CKM will remove backup).
        if (SECURITY_SERVER_PLUGIN_SUCCESS != plugin.login(zone, APP_USER, newPassword)) {
            // It's not critical. We may confirm new password next time user login.
            LogDebug("Confirmation failed!");
        }

        return SECURITY_SERVER_API_SUCCESS;
    }

    int PasswordManager::setPasswordValidity(const std::string &zone,
                                             const unsigned int receivedDays)
    {
        time_t valid_secs = 0;

        LogSecureDebug("received_days: " << receivedDays);

        existPassword(zone);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(zone);

        if (!itPwd->second.isPasswordActive()) {
            LogError("Current password is not active.");
            return SECURITY_SERVER_API_ERROR_NO_PASSWORD;
        }

        if (!calculateExpiredTime(receivedDays, valid_secs))
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

        itPwd->second.setExpireTime(valid_secs);
        itPwd->second.writeMemoryToFile();

        return SECURITY_SERVER_API_SUCCESS;
    }

    int PasswordManager::resetPassword(const std::string &zone,
                                       const std::string &newPassword,
                                       const unsigned int receivedAttempts,
                                       const unsigned int receivedDays,
                                       PluginHandler &plugin)
    {
        time_t valid_secs = 0;

        existPassword(zone);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(zone);

        if (!calculateExpiredTime(receivedDays, valid_secs))
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

        if (newPassword.empty() && (receivedAttempts != 0 || receivedDays != 0)) {
            LogError("Attempts or receivedDays is not equal 0");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        if (SECURITY_SERVER_PLUGIN_SUCCESS != plugin.resetUserPassword(zone, APP_USER, newPassword)) {
            LogError("Password reset was rejected by plugin");
            return SECURITY_SERVER_API_ERROR_PASSWORD_PLUGIN;
        }

        itPwd->second.setPassword(newPassword);
        itPwd->second.setMaxAttempt(receivedAttempts);
        itPwd->second.setExpireTime(valid_secs);
        itPwd->second.writeMemoryToFile();

        itPwd->second.resetAttempt();
        itPwd->second.writeAttemptToFile();

        // unlockUserKey is treated as confirmation of new password by CKM (CKM will remove backup).
        if (SECURITY_SERVER_PLUGIN_SUCCESS != plugin.login(zone, APP_USER, newPassword)) {
            // It's not critical. We may confirm new password next time user login.
            LogDebug("Confirmation failed!");
        }

        return SECURITY_SERVER_API_SUCCESS;
    }

    int PasswordManager::setPasswordHistory(const std::string &zone, const unsigned int history)
    {
        existPassword(zone);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(zone);

        if (history > MAX_PASSWORD_HISTORY) {
            LogError("Incorrect input param.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        itPwd->second.setMaxHistorySize(history);
        itPwd->second.writeMemoryToFile();

        return SECURITY_SERVER_API_SUCCESS;
    }

    int PasswordManager::setPasswordMaxChallenge(const std::string &zone,
                                                 const unsigned int maxChallenge)
    {
        existPassword(zone);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(zone);

        // check if there is password
        if (!itPwd->second.isPasswordActive()) {
            LogError("Password not active.");
            return SECURITY_SERVER_API_ERROR_NO_PASSWORD;
        }

        itPwd->second.setMaxAttempt(maxChallenge);
        itPwd->second.writeMemoryToFile();

        itPwd->second.resetAttempt();
        itPwd->second.writeAttemptToFile();

        return SECURITY_SERVER_API_SUCCESS;
    }
} //namespace SecurityServer
