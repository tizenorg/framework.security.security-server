/*
 *  security-server
 *
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
 *
 */

#ifndef SECURITY_SERVER_ERROR_H
#define SECURITY_SERVER_ERROR_H

/**
 * \name Return Codes
 * exported by the foundation API.
 * result codes begin with the start error code and extend into negative direction.
 * @{
*/
#define SECURITY_SERVER_API_SUCCESS 0
/*! \brief   indicating the result of the one specific API is successful */
#define SECURITY_SERVER_API_ERROR_SOCKET -1

/*! \brief   indicating the socket between client and Security Server has been failed  */
#define SECURITY_SERVER_API_ERROR_BAD_REQUEST -2

/*! \brief   indicating the response from Security Server is malformed */
#define SECURITY_SERVER_API_ERROR_BAD_RESPONSE -3

/*! \brief   indicating the transmitting request has been failed */
/* deprecated unused */
#define SECURITY_SERVER_API_ERROR_SEND_FAILED -4

/*! \brief   indicating the receiving response has been failed */
/* deprecated unused */
#define SECURITY_SERVER_API_ERROR_RECV_FAILED -5

/*! \brief   indicating requesting object is not exist */
#define SECURITY_SERVER_API_ERROR_NO_SUCH_OBJECT -6

/*! \brief   indicating the authentication between client and server has been failed */
#define SECURITY_SERVER_API_ERROR_AUTHENTICATION_FAILED -7

/*! \brief   indicating the API's input parameter is malformed */
#define SECURITY_SERVER_API_ERROR_INPUT_PARAM -8

/*! \brief   indicating the output buffer size which is passed as parameter is too small */
#define SECURITY_SERVER_API_ERROR_BUFFER_TOO_SMALL -9

/*! \brief   indicating system  is running out of memory state */
#define SECURITY_SERVER_API_ERROR_OUT_OF_MEMORY -10

/*! \brief   indicating the access has been denied by Security Server */
#define SECURITY_SERVER_API_ERROR_ACCESS_DENIED -11

/*! \brief   indicating Security Server has been failed for some reason */
#define SECURITY_SERVER_API_ERROR_SERVER_ERROR -12

/*! \brief   indicating given cookie is not exist in the database  */
#define SECURITY_SERVER_API_ERROR_NO_SUCH_COOKIE -13

/*! \brief   indicating there is no phone password set  */
#define SECURITY_SERVER_API_ERROR_NO_PASSWORD -14

/*! \brief   indicating password exists in system  */
#define SECURITY_SERVER_API_ERROR_PASSWORD_EXIST -15

/*! \brief   indicating password mismatch  */
#define SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH -16

/*! \brief   indicating password retry timeout is not occurred yet  */
#define SECURITY_SERVER_API_ERROR_PASSWORD_RETRY_TIMER -17

/*! \brief   indicating password retry timeout is not occurred yet  */
#define SECURITY_SERVER_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED -18

/*! \brief   indicating password retry timeout is not occurred yet  */
#define SECURITY_SERVER_API_ERROR_PASSWORD_EXPIRED -19

/*! \brief   indicating password retry timeout is not occurred yet  */
#define SECURITY_SERVER_API_ERROR_PASSWORD_REUSED -20

/*! \brief   indicating getting smack label from socket failed  */
#define SECURITY_SERVER_API_ERROR_GETTING_SOCKET_LABEL_FAILED -21

/*! \brief   indicating getting smack label from file failed  */
#define SECURITY_SERVER_API_ERROR_GETTING_FILE_LABEL_FAILED -22

/*! \brief   indicating setting smack label for file failed  */
#define SECURITY_SERVER_API_ERROR_SETTING_FILE_LABEL_FAILED -23

/*! \brief   indicating file already exists  */
#define SECURITY_SERVER_API_ERROR_FILE_EXIST -24

/*! \brief   indicating file does not exist  */
#define SECURITY_SERVER_API_ERROR_FILE_NOT_EXIST -25

/*! \brief   indicating file open error  */
#define SECURITY_SERVER_API_ERROR_FILE_OPEN_FAILED -26

/*! \brief   indicating file creation error  */
#define SECURITY_SERVER_API_ERROR_FILE_CREATION_FAILED -27

/*! \brief   indicating file deletion error  */
#define SECURITY_SERVER_API_ERROR_FILE_DELETION_FAILED -28

/*! \brief   inticating that password plugin reject request */
#define SECURITY_SERVER_API_ERROR_PASSWORD_PLUGIN -29

/*! \brief   indicating directory for file creation error  */
#define SECURITY_SERVER_API_ERROR_DIRECTORY_CREATION_FAILED -30

/*! \brief   indicating adding watch to file error  */
#define SECURITY_SERVER_API_ERROR_WATCH_ADD_TO_FILE_FAILED -31

/*! \brief   indicating computing directory size error  */
#define SECURITY_SERVER_API_ERROR_QUOTA_STAT_FAILED -32

/*! \brief   indicating too many files present for label  */
#define SECURITY_SERVER_API_ERROR_QUOTA_NUM_FILES -33

/*! \brief   indicating too many bytes consumed for label  */
#define SECURITY_SERVER_API_ERROR_QUOTA_BYTES -34

/*! \brief   indicating getting zone info for password failed  */
#define SECURITY_SERVER_API_ERROR_GETTING_ZONE_INFO_FAILED -35

/*! \brief   indicating permission database is temporarily locked  */
#define SECURITY_SERVER_API_ERROR_DATABASE_LOCKED -36

/*! \brief   indicating error in configuration  */
#define SECURITY_SERVER_API_ERROR_CONFIGURATION -37

/*! \brief   indicating usage of privileged API by unprivileged user  */
#define SECURITY_SERVER_API_ERROR_OPERATION_NOT_PERMITTED -38

/*! \brief   indicating unspecified database operation error  */
#define SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_OPERATION -39

/*! \brief   indicating that Label is taken by another application  */
#define SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_LABEL_TAKEN -40

/*! \brief   indicating that Query fails during preparing a SQL statement  */
#define SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_QUERY_PREP -41

/*! \brief   indicating that Query fails during binding to a SQL statement  */
#define SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_QUERY_BIND -42

/*! \brief   indicating that Query fails during stepping a SQL statement  */
#define SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_QUERY_STEP -43

/*! \brief   indicating that Unable to establish a connection with the database  */
#define SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_CONNECTION -44

/*! \brief   indicating that There is no application with such app_id  */
#define SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_NO_SUCH_APP -45

/*! \brief   indicating that There already exists a permission with this name and type  */
#define SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_PERM_FORBIDDEN -46

/*! \brief   indicating setting smack ACCESS label for given path failed  */
#define SECURITY_SERVER_API_ERROR_SETTING_ACCESS_LABEL_FAILED -47

/*! \brief   indicating setting smack TRANSMUTE flag for given path failed  */
#define SECURITY_SERVER_API_ERROR_SETTING_TRANSMUTE_FLAG_FAILED -48

/*! \brief   indicating setting ACCESS label failed due to caller not on whitelist */
#define SECURITY_SERVER_API_ERROR_LABEL_NOT_ON_WHITE_LIST -49

/*! \brief   indicating setting ACCESS label failed due to label on blacklist */
#define SECURITY_SERVER_API_ERROR_LABEL_ON_BLACK_LIST -50

/*! \brief   indicating getting smack label failed */
#define SECURITY_SERVER_API_ERROR_GETTING_LABEL -51

/*! \brief   indicating the error with unknown reason */
#define SECURITY_SERVER_API_ERROR_UNKNOWN -255
/** @}*/


#endif
