/*
 *  security-server
 *
 *  Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 */

#ifndef SECURITY_SERVER_H
#define SECURITY_SERVER_H


/**
 * @file    security-server.h
 * @version 1.0
 * @brief   This file contains APIs of the Security Server
*/

/**
 * @defgroup SecurityFW
 * @{
 *
 * @defgroup SECURITY_SERVER Security Server
 * @version  1.0
 * @brief    Security Server client library functions
 *
*/

/**
 * @addtogroup SECURITY_SERVER
 * @{
*/

/*
 * ====================================================================================================
 * <tt>
 *
 * Revision History:
 *
 *  -- Company Name -- | Modification Date | Description of Changes 
 *  ----------------------------------------------------------------------- 
 *   --- Samsung ------ | --- 2010-07-25 -- | First created
 *
 *    </tt>
 */

/**
 * \name Return Codes
 * exported by the foundation API.
 * result codes begin with the start error code and extend into negative direction.
 * @{
*/
#define SECURITY_SERVER_API_SUCCESS			0
/*! \brief   indicating the result of the one specific API is successful */
#define SECURITY_SERVER_API_ERROR_SOCKET		-1

/*! \brief   indicating the socket between client and Security Server has been failed  */
#define SECURITY_SERVER_API_ERROR_BAD_REQUEST		-2

/*! \brief   indicating the response from Security Server is malformed */
#define SECURITY_SERVER_API_ERROR_BAD_RESPONSE		-3

/*! \brief   indicating the transmitting request has been failed */
#define SECURITY_SERVER_API_ERROR_SEND_FAILED		-4

/*! \brief   indicating the receiving response has been failed */
#define SECURITY_SERVER_API_ERROR_RECV_FAILED		-5

/*! \brief   indicating requesting object is not exist */
#define SECURITY_SERVER_API_ERROR_NO_SUCH_OBJECT	-6

/*! \brief   indicating the authentication between client and server has been failed */
#define SECURITY_SERVER_API_ERROR_AUTHENTICATION_FAILED	-7

/*! \brief   indicating the API's input parameter is malformed */
#define SECURITY_SERVER_API_ERROR_INPUT_PARAM		-8

/*! \brief   indicating the output buffer size which is passed as parameter is too small */
#define SECURITY_SERVER_API_ERROR_BUFFER_TOO_SMALL	-9

/*! \brief   indicating system  is running out of memory state */
#define SECURITY_SERVER_API_ERROR_OUT_OF_MEMORY		-10

/*! \brief   indicating the access has been denied by Security Server */
#define SECURITY_SERVER_API_ERROR_ACCESS_DENIED		-11

/*! \brief   indicating Security Server has been failed for some reason */
#define SECURITY_SERVER_API_ERROR_SERVER_ERROR		-12

/*! \brief   indicating given cookie is not exist in the database  */
#define SECURITY_SERVER_API_ERROR_NO_SUCH_COOKIE	-13

/*! \brief   indicating there is no phone password set  */
#define SECURITY_SERVER_API_ERROR_NO_PASSWORD		-14

/*! \brief   indicating password exists in system  */
#define SECURITY_SERVER_API_ERROR_PASSWORD_EXIST		-15

/*! \brief   indicating password mismatch  */
#define SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH	-16

/*! \brief   indicating password retry timeout is not occurred yet  */
#define SECURITY_SERVER_API_ERROR_PASSWORD_RETRY_TIMER	-17

/*! \brief   indicating password retry timeout is not occurred yet  */
#define SECURITY_SERVER_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED	-18

/*! \brief   indicating password retry timeout is not occurred yet  */
#define SECURITY_SERVER_API_ERROR_PASSWORD_EXPIRED	-19

/*! \brief   indicating password retry timeout is not occurred yet  */
#define SECURITY_SERVER_API_ERROR_PASSWORD_REUSED	-20

/*! \brief   indicating the error with unknown reason */
#define SECURITY_SERVER_API_ERROR_UNKNOWN		-255
/** @}*/


#ifdef __cplusplus
extern "C" {
#endif



/**
 * \par Description:
 * Retreives Linux group ID from object name which is passed by parameter
 *
 * \par Purpose:
 * This API may be used before security_server_check_privilege() API by middleware daemon to get group ID of a specific object.
 *
 * \par Typical use case:
 * In middleware daemon, before checking privilege of a service the daemon need to know the GID of the service. This API support the functionality.
 *
 * \par Method of function operation:
 * Opens /etc/group file and searches the object name as group name. If there is matching result, returns GID as integer
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * - This API is only allowed to be called by pre-defined middleware daemon
 *
 * \param[in] object Name of the object which is kwnown by the caller.
 *
 * \return matching gid (positive integer) on success, or negative error code on error.
 * 
 * \par Prospective clients:
 * Inhouse middleware
 *
 * \par Known issues/bugs:
 * None
 * 
 * \pre None
 * 
 * \post None
 *
 * \see /etc/group,
 * security_server_get_object_name(), security_server_check_privilege()
 * 
 * \remarks None
 * 
 * \par Sample code:
 * \code
 * #include <security-server.h>
 * ...
 * int retval;
 *
 * // You have to make sure that  the input param '*object' is defined in the platform
 * retval = security_server_get_gid("telephony_makecall");
 * if(retval < 0)
 * {
 * 	printf("%s", "Error has occurred\n");
 * 	exit(0);
 * }
 * ...
 * \endcode
*/
int security_server_get_gid(const char *object);



/**
 * \par Description:
 * Retreives object name as mull terminated string from Linux group ID which is passed by parameter
 *
 * \par Purpose:
 * This API may be used to get object name if the caller process only knows GID of the object.
 *
 * \par Typical use case:
 * In middleware daemon, by some reason, need to know object name from the Linux group ID, then call this API to retrieve object name as string
 *
 * \par Method of function operation:
 * Opens /etc/group file and searches matching gid. If there is matching result, returns name of the group as null terminated string
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * - This API is only allowed to be called by pre-defined middleware daemon
 *
 * \param[in] gid Linux group ID which needed to be retrieved as object name.
 * \param[out] object Place holder for matching object name for gid.
 * \param[in] max_object_size Allocated byte size of parameter "object".
 *
 * \return 0 on success, or negative error code on error.
 * 
 * \par Prospective clients:
 * Inhouse middleware.
 *
 * \par Known issues/bugs:
 * None
 * 
 * \pre output parameter object must be malloced before calling this API not to make memory curruption
 * 
 * \post None
 *
 * \see /etc/group,
 * security_server_get_gid()
 * 
 * \remarks None
 * 
 * \par Sample code:
 * \code
 * #include <security-server.h>
 * ...
 * int retval;
 * char objectname[20];
 * 
 * // Call the API
 * retval = security_server_get_object_name(6005, objectname, sizeof(objectname));
 * if(retval < 0)
 * {
 * 	printf("%s", "Error has occurred\n");
 * 	exit(0);
 * }
 * ...
 * \endcode
*/
int security_server_get_object_name(gid_t gid, char *object, size_t max_object_size);



/**
 * \par Description:
 * Request cookie to the Security Server. Cookie is a random bit stream which is used as ticket for user space object.
 *
 * \par Purpose:
 * This API may be used by application and client middleware process to get access to middleware daemons.
 *
 * \par Typical use case:
 * When an application process wants to get access to some middleware object, first call this API to get cookie value. Then it calls the service API to get service with the cookie value.
 *
 * \par Method of function operation:
 * Caller process just send request message. Security Server checks proc file system to get list of gIDs the caller belongs, then create a random cookie and responds to caller.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * Cookie needs to be stored relatively secure.
 *
 * \param[out] cookie Place holder for cookie value.
 * \param[in] max_cookie Allocated byte size of parameter "cookie".
 *
 * \return 0 on success, or negative error code on error.
 * 
 * \par Prospective clients:
 * Any process
 *
 * \par Known issues/bugs:
 * None
 * 
 * \pre output parameter cookie must be malloced before calling this API not to make memory curruption
 * Size of the cookie can be retrieved by security_server_get_cookie_size() API.
 * 
 * \post None
 *
 * \see security_server_check_privilege(), security_server_get_cookie_size()
 * 
 * \remarks None
 * 
 * \par Sample code:
 * \code
 * #include <security-server.h>
 * ...
 * int retval;
 * size_t cookie_size;
 * cookie_size = security_server_get_cookie_size();
 * unsigned char cookie[cookie_size];
 *
 * // Call the API
 * retval = security_server_request_cookie(cookie, cookie_size);
 * if(retval < 0)
 * {
 * 	printf("%s", "Error has occurred\n");
 * 	exit(0);
 * }
 * ...
 * \endcode
*/
int security_server_request_cookie(char *cookie, size_t max_cookie);



/**
 * \par Description:
 * This API gets the cookie's byte size which is issued by Security Server.
 *
 * \par Purpose:
 * This API may be used by application and middleware process to get size of cookie before getting and storing cookie value.
 *
 * \par Typical use case:
 * When an application process wants to get access to some middleware object, first call this API to get cookie value. Then it calls the service API to get service with the cookie value.
 *
 * \par Method of function operation:
 * This API just returns pre-defined integer value as cookie size.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * None
 *
 * \return Always returns byte size of the cookie. 
 * 
 * \par Prospective clients:
 * Any process
 *
 * \par Known issues/bugs:
 * None
 * 
 * \pre None
 * 
 * \post None
 *
 * \see security_server_request_cookie()

 * \remarks None
 * 
 * \par Sample code:
 * \code
 * #include <security-server.h>
 * ...
 * int retval;
 * size_t cookie_size;
 *
 * // API calling
 * cookie_size = security_server_get_cookie_size();
 * unsigned char cookie[cookie_size];
 * 
 * char objectname[20];
 * retval = security_server_request_cookie(cookie, cookie_size);
 * if(retval < 0)
 * {
 * 	printf("%s", "Error has occurred\n");
 * 	exit(0);
 * }
 * ...
 * \endcode
*/
int security_server_get_cookie_size(void);



/**
 * \par Description:
 * This API checks the cookie is allowed to access to given object.
 *
 * \par Purpose:
 * This API may be used by middleware process to ask the client application has privilege for the given object.
 *
 * \par Typical use case:
 * When middleware server receives request message from client application process with cookie value, it calls this API to ask to Security Server that the client application has privilege to access the service. If yes, then the middleware daemon can continue service, if not, it can return error to client application.
 *
 * \par Method of function operation:
 * When Security Server receives this request, it searches cookie database and check the cookie is there, if there is matching cookie, then it checks the cookie has the privilege. It returns success if there is match, if not, it returns error.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * Cookie value needs to be stored relatively secure\n
 * Privilege should be pre-defined by Platform design.
 *
 * \param[in] cookie Received cookie value from client application
 * \param[in] privilege Object group ID which the client application wants to access
 *
 * \return 0 on success, or negative error code on error.
 * 
 * \par Prospective clients:
 * Only pre-defiend middleware daemons
 *
 * \par Known issues/bugs:
 * None
 * \pre None
 * 
 * \post None
 *
 * \see security_server_request_cookie(), security_server_get_gid(), security_server_get_cookie_size()
 *  
 * \remarks None
 *  
 * \par Sample code:
 * \code
 * #include <security-server.h>
 * ...
 * int retval;
 * size_t cookie_size;
 * int call_gid;
 * cookie_size = security_server_get_cookie_size();
 * unsigned char recved_cookie[cookie_size];
 * 
 * ... // Receiving request with cookie
 *
 * call_gid = security_server_get_gid("telephony_makecall");
 * retval = security_server_check_privilege(recved_cookie, (gid_t)call_gid);
 * if(retval < 0)
 * {
 * 	if(retval == SECURITY_SERVER_API_ERROR_ACCESS_DENIED)
 * 	{
 * 		printf("%s", "access has been denied\n");
 * 		return;
 * 	}
 * 	printf("%s", "Error has occurred\n");
 * }
 * ...
 *
 * \endcode
*/
int security_server_check_privilege(const char *cookie, gid_t privilege);



/**
 * \par Description:
 * This API searchs a cookie value and returns PID of the given cookie.
 *
 * \par Purpose:
 * This API may be used by middleware process to ask the client application has privilege for the given object.
 *
 * \par Typical use case:
 * In some cases, a middleware server wants to know PID of the application process. But if the middleware server uses non-direct IPC such as dbus, it's nearly impossible to know and guarantee peer PID. By using this API, the middleware server can retrieve a PID of the requesting process.
 *
 * \par Method of function operation:
 * When Security Server receives this request, it searches cookie database and check the cookie is there, if there is matching cookie, then it returns corresponding PID for the cookie.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * Cookie value needs to be stored relatively secure\n
 * This API is abled to be called only by pre-defined middleware servers.
 *
 * \param[in] cookie Received cookie value from client application. Cookie is not a null terminated human readable string. Make sure you're code doesn't have any string related process on the cookie.
 *
 * \return positive integer on success meaning the PID, 0 means the cookie is for root process, negative integer error code on error.
 * 
 * \par Prospective clients:
 * Only pre-defiend middleware daemons
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 * 
 * \post None
 *
 * \see security_server_request_cookie(), security_server_get_cookie_size()
 *  
 * \remarks the cookie is not a null terminated string. Cookie is a BINARY byte stream of such length which can be retrieved by security_server_get_cookie_size() API.
 * Therefore, please do not use strcpy() family to process cookie value. You MUST use memcpy() function to process cookie value.
 * You also have to know that the cookie value doesn't carry any null terminator. So you don't need to allocate 1 more byte of the cookie size.
 *  
 * \par Sample code:
 * \code
 * #include <security-server.h>
 * ...
 * int peerpid;
 * size_t cookie_size;
 * gid_t call_gid;
 * cookie_size = security_server_get_cookie_size();
 * unsigned char recved_cookie[cookie_size];
 * 
 * ... // Receiving request with cookie
 *
 * peerpid = security_server_get_cookie_pid(recved_cookie);
 * if(peerpid < 0)
 * {
 * 	printf("%s", "Error has occurred\n");
 * }
 * ...
 *
 * \endcode
*/
int security_server_get_cookie_pid(const char *cookie);



/**
 * \par Description:
 * This API checks phone validity of password, to check existance, expiration, remaining attempts.
 *
 * \par Purpose:
 * This API should be used by applications which needs phone password check. Caller application should behave properly after this API call.
 *
 * \par Typical use case:
 * Lock screen can call this API before it shows unlock screen, if there is password, lock screen can show password input UI, if not, lock screen can show just unlock screen
 *
 * \par Method of function operation:
 * Sends a validate request to security server and security server replies with password information.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * Password file should be stored safely. The password file will be stored by security server and only allowed itself to read/write, and data is will be securely hashed\n
 *
 * \param[out] current_attempts Number of password check missed attempts. 
 * \param[out] max_attempts Number of maximum attempts that the password locks. 0 means infinite
 * \param[out] valid_secs Remaining time in second which represents this password will be expired. 0xFFFFFFFF means infinite
 *
 * \return 0 if there is no password set, other negative integer error code on error.
 * 
 * \par Prospective clients:
 * Applications which can unlock UI
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 * 
 * \post None
 *
 * \see security_server_set_pwd(), security_server_chk_pwd()
 *  
 * \remarks If password file is currupted or accitentally deleted, this API may not synchronized with security-server, but security-server will check file status on next request.
 *  
 * \par Sample code:
 * \code
 * #include <security-server.h>
 * ...
 * int ret;
 * unsigned int attempt, max_attempt, expire_sec;
 *
 * ret = security_server_is_pwd_valid(&attempt, &max_attempt, &expire_sec);
 * if(is_pwd_set == SECURITY_SERVER_API_ERROR_NO_PASSWORD)
 * {
 * 	printf("%s", "There is no password exists\n");
 * }
 * else if(is_pwd_set == SECURITY_SERVER_SUCCESS && expire_sec > 0 && attempt < max_attempts)
 * {
 *	printf("%s", "Password is valid by now\n");
 * }
 * else
 * {
 *	printf("%s", "Something wrong\n");
 * }
 * ...
 *
 * \endcode
*/
int security_server_is_pwd_valid(unsigned int *current_attempts, 
			unsigned int *max_attempts, 
			unsigned int *valid_secs);



/**
 * \par Description:
 * This API sets phone password only if current password matches.
 *
 * \par Purpose:
 * This API should be used by setting application when the user changes his/her phone password.
 *
 * \par Typical use case:
 * Setting application calls this API to change phone password. Caller needs current password to grant the change.
 *
 * \par Method of function operation:
 * Sends current password with new password to security-server, security-server checks current password and set new password to current only when current password is correct. Caller application can determine maximum number of attempts and expiration time in days
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * There is retry timer on this API to limit replay attack. You will get error if you called this API too often.\n
 *
 * \param[in] cur_pwd Null terminated current password string. It can be NULL pointer if there is no password set yet - by calling security_server_is_pwd_empty()
 * \param[in] new_pwd Null terminated new password string. It must not a NULL pointer.
 * \param[in] max_challenge Maximum number of attempts that user can try to check the password without success in serial. 0 means infinity.
 * \param[in] valid_period_in_days. Number of days that this password is valid. 0 means infinity
 *
 * \return 0 on seccuess, negative integer error code on error.
 * 
 * \par Prospective clients:
 * Platform's THE ONLY setting application and some dedicated privileged processes
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 * 
 * \post None
 *
 * \see security_server_is_pwd_valid(), security_server_chk_pwd(), security_server_reset_pwd()
 *  
 * \remarks Only setting application can call this API. The password file will be acces controlled and securely hashed. Security-server will remain previous password file to recover unexpected password file curruption.
 * \remarks If current password exists and it's expired, or max attempts reached, you cannot call this API. You have to call security_server_reset_pwd() API.
 *  
 * \par Sample code:
 * \code
 * #include <security-server.h>
 * ...
 * int ret;
 * unsigned int attempt, max_attempt, expire_sec;
 *
 * ret = security_server_is_pwd_valid(&attempt, &max_attempt, &expire_sec);
 * if(is_pwd_set == SECURITY_SERVER_API_ERROR_NO_PASSWORD)
 * {
 * 	printf("%s", "There is no password exists\n");
 *	ret = security_server_set_pwd(NULL, "this_is_new_pwd", 20, 365);
 * 	if(ret != SECURITY_SERVER_API_SUCCESS)
 * 	{
 * 		printf("%s", "we have error\n");
 * 		...
 * 	}
 * }
 * else if(is_pwd_set == SECURITY_SERVER_SUCCESS && expire_sec > 0 && attempt < max_attempts)
 * {
 *	printf("%s", "Password is valid by now\n");
 * 	ret = security_server_set_pwd("this_is_current_pwd", "this_is_new_pwd", 20, 365);
 * 	if(ret != SECURITY_SERVER_API_SUCCESS)
 * 	{
 * 		printf("%s", "we have error\n");
 * 		...
 * 	}
 * }
 * else
 * {
 *	printf("%s", "Something wrong\n");
 * }
 * ...
 *
 * \endcode
*/
int security_server_set_pwd(const char *cur_pwd,
			const char *new_pwd, 
			const unsigned int max_challenge, 
			const unsigned int valid_period_in_days);



/**
 * \par Description:
 * This API sets phone password only if current password is invalid or user forgot the password.
 *
 * \par Purpose:
 * This API should be used by setting application or dedicated processes when the user changes his/her phone password.
 *
 * \par Typical use case:
 * User forgots the password. He calls emergency manager(auto or manual)  for reset password. Emergency manager calls this API and reset phone password.
 *
 * \par Method of function operation:
 * Resetting phone password with input string without any matching current password.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * There is retry timer on this API to limit replay attack. You will get error if you called this API too often.\n
 *
 * \param[in] new_pwd Null terminated new password string. It must not a NULL pointer.
 * \param[in] max_challenge Maximum number of attempts that user can try to check the password without success in serial. 0 means infinity.
 * \param[in] valid_period_in_days. Number of days that this password is valid. 0 means infinity
 *
 * \return 0 on seccuess, negative integer error code on error.
 * 
 * \par Prospective clients:
 * Platform's THE ONLY setting application and some dedicated privileged processes
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 * 
 * \post None
 *
 * \see security_server_is_pwd_valid(), security_server_chk_pwd(), security_server_set_pwd()
 *  
 * \remarks Only dedicated applications can call this API. The password file will be acces controlled and securely hashed. Security-server will remain previous password file to recover unexpected password file curruption.
 *  
 * \par Sample code:
 * \code
 * #include <security-server.h>
 * ...
 * int ret;
 * unsigned int attempt, max_attempt, expire_sec;
 *
 * 	ret = security_server_set_pwd("this_is_new_pwd", 20, 365);
 * 	if(retval != SECURITY_SERVER_API_SUCCESS)
 * 	{
 * 		printf("%s", "we have error\n");
 * 		...
 * 	}
 * ...
 *
 * \endcode
*/
int security_server_reset_pwd(const char *new_pwd,
			const unsigned int max_challenge, 
			const unsigned int valid_period_in_days);

/**
 * \par Description:
 * This API compares stored phone password with challenged input value.
 *
 * \par Purpose:
 * This API should be used by applications which has phone UI lock capability.
 *
 * \par Typical use case:
 * Lock screen calls this API after user typed phone password and pressed okay.
 *
 * \par Method of function operation:
 * Sends challenged password to security-server, security-server compares hashed current password and hashed challenged password.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * There is retry timer on this API to limit replay attack. You will get error if you called this API too often.\n
 *
 * \param[in] challenge Null terminated challenged password string. It must not a NULL pointer.
 * \param[out] current_attempts Number of password check missed attempts. 
 * \param[out] max_attempts Number of maximum attempts that the password locks. 0 means infinite
 * \param[out] valid_secs Remaining time in second which represents this password will be expired. 0xFFFFFFFF means infinite
 *
 * \return 0 on seccuess, negative integer error code on error.
 * 
 * \par Prospective clients:
 * Applications which has phone UI lock feature.
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 * 
 * \post None
 *
 * \see security_server_is_pwd_valid(), security_server_set_pwd()
 *  
 * \remarks The password file will be acces controlled and securely hashed. Security-server will remain previous password file to recover unexpected password file curruption.
 *  
 * \par Sample code:
 * \code
 * #include <security-server.h>
 * ...
 * int retval;
 * unsigned int attempt, max_attempt, expire_sec; 
 *
 * retval = security_server_chk_pwd("is_this_password", &attmpt, &max_attempt, &expire_sec);
 * if(retval == SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH)
 * {
 * 	printf("%s", "Oh you typed wrong password\n");
 * 	...
 * }
 * else if(retval == SECURITY_SERVER_API_SUCCESS)
 * {
 * 	printf("%s", "You remember your password.\n");
 * 	...
 * }
 * ...
 *
 * \endcode
*/
int security_server_chk_pwd(const char *challenge, 
			unsigned int *current_attempt, 
			unsigned int *max_attempt, 
			unsigned int *valid_secs);


/**
 * \par Description:
 * This API set the number of password history which should be maintained. Once this number set, user cannot reuse recent number of passwords which is described in this history value
 *
 * \par Purpose:
 * This API should be used only by dedicated process in the platform.
 *
 * \par Typical use case:
 * Enterprise manager calls this API when the enterprise wants to enforce harder password policy.
 *
 * \par Method of function operation:
 * When enterprise manager (MDM) is trying to change the security policy for phone password, it calls this API background to change the history policy.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * There is retry timer on this API to limit replay attack. You will get error if you called this API too often.\n
 *
 * \param[in] number_of_history Number of history to be checked when user tries to change password. Maximum is currently 50
 *
 * \return 0 on seccuess, negative integer error code on error.
 * 
 * \par Prospective clients:
 * MDM client, Enterprise manager.
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 * 
 * \post None
 *
 * \see security_server_set_pwd()
 *  
 * \remarks The password file will be acces controlled and securely hashed. Security-server will remain previous password file to recover unexpected password file curruption.
 *  
 * \par Sample code:
 * \code
 * #include <security-server.h>
 * ...
 * int retval;
 *
 * ret = security_server_set_pwd_history(100);
 *	if(ret != SECURITY_SERVER_API_SUCCESS)
 *	{
 *		printf("%s", "You have error\n");
 *		...
 *	}
 * ...
 *
 * \endcode
*/
int security_server_set_pwd_history(int number_of_history);



/**
 * \par Description:
 * This API launches /usr/bin/debug-util as root privilege.
 *
 * \par Purpose:
 * This API will be used only by SDK with developer privilege to launch debugging tool to debug as the developing applicaion's privilege.
 *
 * \par Typical use case:
 * During appliation development, SDK opens a shell to install, launch, and debug the developing application. But the shell will not have any privilege to control platform. Therefore we need a special utility to manage debugging environement as same privilege level of the application. If this API is called, security server will launch the debug utility as root privilege and the utility will drop its privilege same as developing application
 *
 *
 * \par Method of function operation:
 * When Security Server receives this request, it checks uid of the client, and launches /usr/bin/debug-util with given arguements.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * Caller process of this API must be owned by developer user.\n
 * The caller process will be pre-defined.
 * /usr/bin/debug-util itself must be omitted in the argv. Security server will put this as first argv in the execution procedure
 *
 * \param[in] argc Number of arguements.
 * 
 * \param[in] argv Arguements
 *
 * \return 0 on success, negative integer error code on error.
 * 
 * \par Prospective clients:
 * Only pre-defiend debugging utility.
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 * 
 * \post None
 *
 * \see None
 *  
 * \remarks Calling this API, you have to put argv[1] of the debug-util as argv[0] of this API. Security server will put argv[0] automatically
 *  
 * \par Sample code:
 * \code
 * #include <security-server.h>
 * #define DEVELOPER_UID 5500
 *
 * int main(int argc, char **argv)
 * {
 * 	int my_uid, ret;
 * 	uid = getuid();
 * 	if(uid != DEVELOPER_UID)
 * 	{
 * 		// You must be developer user
 * 		exit(1);
 * 	}
 *
 * 	ret = security_server_launch_debug_tool(argc -1, argv++)
 * 	if(ret != SECURITY_SERVER_SUCCESS)
 * 	{
 * 		// Some error occurred
 * 		exit(1);
 * 	}
 * 	...
 * }
 *
 * \endcode
*/
int security_server_launch_debug_tool(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

/**
 * @}
*/

/**
 * @}
*/

#endif	