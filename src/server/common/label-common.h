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
 *
 * @file        label-common.h
 * @author      Zofia Abramowska <z.abramowska@samsung.com>
 * @version     1.0
 * @brief       Declaration of common functions for label client and service.
 */

#ifndef SECURITY_SERVER_LABEL_COMMON_H_
#define SECURITY_SERVER_LABEL_COMMON_H_

#include <string>

namespace SecurityServer {

int smackRuntimeCheck();
int labelAccess(const std::string &path, const std::string &label);
int labelTransmute(const std::string &path, int transmute_flag);

} /* namespace SecurityServer */

#endif /* SECURITY_SERVER_LABEL_COMMON_H_ */
