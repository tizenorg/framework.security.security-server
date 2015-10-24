IF (TIZEN_ZONE_ENABLED)
    SET(ZONE_PKGS
       vasum
       )
ENDIF (TIZEN_ZONE_ENABLED)


PKG_CHECK_MODULES(COMMON_DEP
    dlog
    ${ZONE_PKGS}
    libiri
    libsmack
    sqlite3
    REQUIRED
    )

SET(COMMON_PATH ${PROJECT_SOURCE_DIR}/src/server)

SET(COMMON_SOURCES
    ${COMMON_PATH}/common/configuration.cpp
    ${COMMON_PATH}/common/error-description.cpp
    ${COMMON_PATH}/common/label-common.cpp
    ${COMMON_PATH}/common/protocols.cpp
    ${COMMON_PATH}/common/permission-types.cpp
    ${COMMON_PATH}/common/message-buffer.cpp
    ${COMMON_PATH}/common/smack-check.cpp
    ${COMMON_PATH}/common/zone-check.cpp
    ${COMMON_PATH}/dpl/log/src/abstract_log_provider.cpp
    ${COMMON_PATH}/dpl/log/src/dlog_log_provider.cpp
    ${COMMON_PATH}/dpl/log/src/log.cpp
    ${COMMON_PATH}/dpl/log/src/old_style_log_provider.cpp
    ${COMMON_PATH}/dpl/log/src/audit-smack-log.cpp
    ${COMMON_PATH}/dpl/core/src/assert.cpp
    ${COMMON_PATH}/dpl/core/src/binary_queue.cpp
    ${COMMON_PATH}/dpl/core/src/colors.cpp
    ${COMMON_PATH}/dpl/core/src/exception.cpp
    ${COMMON_PATH}/dpl/core/src/noncopyable.cpp
    ${COMMON_PATH}/dpl/core/src/serialization.cpp
    ${COMMON_PATH}/dpl/core/src/singleton.cpp
    )

SET_SOURCE_FILES_PROPERTIES(
    ${COMMON_SOURCES}
    PROPERTIES
        COMPILE_FLAGS "-fvisibility=default"
    )

SET(PRIVILEGE_SOURCES
    ${COMMON_PATH}/privilege/common.c
    ${COMMON_PATH}/privilege/privilege-control.c
    ${COMMON_PATH}/privilege/rules-db-internals.c
    ${COMMON_PATH}/privilege/rules-db.c
    ${COMMON_PATH}/privilege/utils.c
    )

SET_SOURCE_FILES_PROPERTIES(
    ${PRIVILEGE_SOURCES}
    PROPERTIES
        COMPILE_FLAGS "-fvisibility=hidden"
    )

INCLUDE_DIRECTORIES(SYSTEM
    ${COMMON_DEP_INCLUDE_DIRS}
    )

INCLUDE_DIRECTORIES(
    ${COMMON_PATH}/common
    ${COMMON_PATH}/dpl/core/include
    ${COMMON_PATH}/dpl/log/include
    ${COMMON_PATH}/privilege
    )

ADD_LIBRARY(${TARGET_SERVER_COMMON} SHARED ${COMMON_SOURCES} ${PRIVILEGE_SOURCES})

SET_TARGET_PROPERTIES(
    ${TARGET_SERVER_COMMON}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC"
        SOVERSION 1.0.0
        VERSION 1.0.0
    )

TARGET_LINK_LIBRARIES(${TARGET_SERVER_COMMON}
    ${COMMON_DEP_LIBRARIES}
    "-lcap -lcrypt"
    )

################################################################################

INSTALL(TARGETS ${TARGET_SERVER_COMMON} DESTINATION lib)
