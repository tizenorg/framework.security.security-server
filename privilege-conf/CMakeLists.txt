# Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# @file        CMakeLists.txt
# @author      Lukasz Wojciechowski <l.wojciechow@partner.samsung.com>
# @brief       Recipes for installation of smack default labeling binaries
#

###################################################################################################
INSTALL(FILES smack_default_labeling DESTINATION /etc/rc.d/init.d/)
INSTALL(FILES capability_setting DESTINATION /etc/rc.d/init.d/)
INSTALL(FILES apply_onlycap.sh DESTINATION /etc/rc.d/init.d/)

IF(NOT "${PROFILE_TYPE}" STREQUAL "TV")
IF(REPOSITORY MATCHES "NON_EMUL")
    INSTALL(FILES onlycap_list DESTINATION /usr/share/privilege-control/)
ELSEIF(REPOSITORY MATCHES "EMULATOR")
    INSTALL(FILES onlycap_list_emul DESTINATION /usr/share/privilege-control/ RENAME onlycap_list)
ENDIF()
ENDIF()
