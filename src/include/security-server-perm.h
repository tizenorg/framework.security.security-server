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
 */

#ifndef SECURITY_SERVER_PERM_H
#define SECURITY_SERVER_PERM_H

#include <stdarg.h>
#include <sys/types.h>
#include <security-server-error.h>
#include <security-server-perm-types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ss_transaction ss_transaction;

/*
 * Initialize security-server transaction. Value of *transaction should be NULL.
 *
 * \param[out] transaction Security server permission transaction
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_begin(ss_transaction **transaction);

/*
 * Initialize security-server offline transaction. Value of *transaction should be NULL.
 * All operations in this transaction will be performed off-line, without calling
 * security-server daemon.
 *
 * \param[out] transaction Security server permission transaction
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Usage of off-line transactions requires CAP_MAC_OVERRIDE capability
 */
int security_server_perm_begin_offline(ss_transaction **transaction);

/*
 * Finalize and destroy security-server transaction. This will commit all modifications made by
 * security-server-perm APIs if success code is returned.
 *
 * \param[in] transaction Security server permission transaction
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_commit(ss_transaction **transaction);

/*
 * Rollback and destroy security-server transaction. This will rollback all modifications made by
 * security-server-perm APIs.
 *
 * \param[in] transaction Security server permission transaction
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_rollback(ss_transaction **transaction);

/*
 * Adds an application to the database if it doesn't already exist. Must be called within
 * security server transaction started with security_server_perm_begin(). It may be called
 * more than once during installation.
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] pkg_id Application identifier
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_install(ss_transaction *transaction, const char *pkg_id);

/*
 * Removes an application from the database with it's permissions, rules and
 * directories, enabling future installation of the application with the same
 * pkg_id. It is needed for tracking lifetime of an application. It must be
 * called within database transaction started with security_server_perm_begin()
 * and finished with security_server_perm_commit().
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] pkg_id Application identifier
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_uninstall(ss_transaction *transaction, const char *pkg_id);

/**
 * Grants SMACK permissions to an application, based on permissions list. It was
 * intended to be called during that application installation. Permissions
 * granted as volatile will not be present after system boot. It must be called
 * within database transaction started with security_server_perm_begin()
 * and finished with security_server_perm_commit().
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] pkg_id Application identifier
 * \param[in] app_type application type
 * \param[in] perm_list Array of permission names, last element must be NULL
 * \param[in] persistent Boolean for choosing between persistent and temporary rules
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_enable_permissions(ss_transaction *transaction,
                                                const char* pkg_id,
                                                app_type_t app_type,
                                                const char** perm_list,
                                                bool persistent);

/**
 * Removes previously granted SMACK permissions based on permissions list.
 * It will remove given permissions from an application, leaving other granted
 * permissions untouched. Results will be persistent. It must be called within
 * database transaction started with security_server_perm_begin()
 * and finished with security_server_perm_commit().
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] pkg_id Application identifier
 * \param[in] app_type application type
 * \param[in] perm_list Array of permission names, last element must be NULL
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_disable_permissions(ss_transaction *transaction,
                                                 const char* pkg_id,
                                                 app_type_t app_type,
                                                 const char** perm_list);

/**
 * Removes all application's permissions, rules and directories registered in
 * the database. It must be called within database transaction started with
 * security_server_perm_begin() and finished with security_server_perm_commit().
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] pkg_id Application identifier
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_revoke_permissions(ss_transaction *transaction, const char* pkg_id);


/**
 * Removes all application's permissions which are not persistent.
 * It must be called within database transaction started with
 * security_server_perm_begin() and finished with security_server_perm_commit().
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] pkg_id Application identifier
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_reset_permissions(ss_transaction *transaction, const char* pkg_id);

/**
 * Checks if an application has the privilege that is specified by the name.
 * It must be called by privileged user.
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] pkg_id application identifier
 * \param[in] app_type application type
 * \param[in] permission_name permission name
 * \param[out] is_enabled bool value stating if permission is enabled
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_has_permission(ss_transaction *transaction,
                                            const char *pkg_id,
                                            app_type_t app_type,
                                            const char *permission_name,
                                            bool *is_enabled);

/**
 * Get the list of the permissions for given application type
 * Caller is responsible for freeing allocated memory.
 * *ppp_permissions is a pointer to an array consisting of char pointers,
 * terminated with NULL pointer. Memory allocated with each
 * of these pointer except for the last one (NULL) should be freed,
 * followed by freeing *ppp_permissions itself.
 *
 * \param[in] transaction Security server permission transaction
 * \param[out] ppp_permissions placeholder for permissions list
 * \param[in] app_type application type
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_get_permissions(ss_transaction *transaction,
                                         char ***ppp_permissions,
                                         app_type_t app_type);

/**
 * Get the list of the applications of given type with particular permission.
 * Caller is responsible for freeing allocated memory
 * using security_server_perm_free_apps_list()
 *
 * \param[in] transaction Security server permission transaction
 * \param[out] pp_apps placeholder for list of application's statuses
 * \param[out] pi_apps_number placeholder for number of found application
 * \param[in] app_type application type
 * \param[in] s_permission_name permission name
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_get_apps_with_permission(ss_transaction *transaction,
                                                  perm_app_status_t **pp_apps,
                                                  size_t *pi_apps_number,
                                                  app_type_t app_type,
                                                  const char *s_permission_name);

/**
 * Free the list of the applications allocated with
 * security_server_perm_get_apps_with_permission().
 *
 * \param[in] pp_apps list of application's statuses
 * \param[in] i_apps_number number of applications on the list
 */
void security_server_perm_free_apps_list(perm_app_status_t *pp_apps, size_t i_apps_number);

/**
 * Get permissions for the specified app.
 *
 * In case of success caller is responsible for freeing memory allocated by it.
 * Each cell in *ppp_perm_list except for the last (NULL) should be freed, followed by freeing
 * *ppp_perm_list itself.
 *
 * In case of error an error code is returned and, provided that ppp_perm_list is not NULL,
 * *ppp_perm_list is set to NULL.
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] pkg_id application identifier
 * \param[in] app_type application type
 * \param[out] ppp_perm_list placeholder for list of permissions
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_get_permissions(ss_transaction *transaction,
                                             const char *pkg_id,
                                             app_type_t app_type,
                                             char ***ppp_perm_list);

/**
 * Sets SMACK labels for an application directory (recursively) or for an executable/symlink
 * file. The exact behavior depends on app_path_type argument:
 *      - APP_PATH_PRIVATE: label with app's label, set access label on everything
 *    and execute label on executable files and symlinks to executable files
 *
 *      - APP_PATH_GROUP: label with given shared_label, set access label on
 *        everything and enable transmute on directories. Also give pkg_id full access
 *        to the shared label.
 *
 *      - APP_PATH_PUBLIC: label with autogenerated label, set access label on
 *        everything and enable transmute on directories. Give full access to the label to
 *        pkg_id and RX access to all other applications.
 *
 *      - APP_PATH_SETTINGS: label with autogenerated label, set access label on
 *        everything and enable transmute on directories. Give full access to the label to
 *        pkg_id and RWX access to all appsetting applications.
 *
 *      - PERM_APP_PATH_NPRUNTIME: label executable file or symlink to an exec given in path param
 *        with label "<pkg_id>.npruntime". Set execute label on it.
 *        Give pkg_id RW access to new created label and give new label RXAT access to pkg_id.
 *
 *      - APP_PATH_ANY_LABEL: label with given shared_label. Set access label on
 *        everything and execute label on executable files and symlinks to
 *        executable files.
 *
 * This function should be called during application installation. Results will
 * be persistent on the file system. It must be called within database transaction
 * started with security_server_perm_begin() and finished with security_server_perm_end().
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] pkg_id application identifier
 * \param[in] path file or directory path
 * \param[in] app_path_type application path type
 * \param[in] ap optional argument for APP_PATH_GROUP_RW and
 *                        APP_PATH_ANY_LABEL path type; type is const char*
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_setup_path(ss_transaction *transaction,
                                        const char* pkg_id,
                                        const char* path,
                                        app_path_type_t app_path_type,
                                        ...);
int security_server_perm_app_setup_path_v(ss_transaction *transaction,
                                          const char* pkg_id,
                                          const char* path,
                                          app_path_type_t app_path_type,
                                          va_list ap);

/**
 * Get paths of the specified type for the given application.
 *
 * Provided type must be one of PERM_APP_PATH_GROUP, PERM_APP_PATH_PUBLIC, PERM_APP_PATH_SETTINGS,
 * PERM_APP_PATH_NPRUNTIME, as other types are not stored in the database.
 *
 * In case of success caller is responsible for freeing memory allocated by it.
 * Each cell in *ppp_paths except for the last (NULL) should be freed, followed by freeing
 * *ppp_paths itself.
 *
 * In case of error an error code is returned and, provided that ppp_paths is not NULL,
 * *ppp_paths is set to NULL.
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] pkg_id application identifier
 * \param[in] app_path_type type of path
 * \param[out] ppp_paths placeholder for list of paths
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_get_paths(ss_transaction *transaction,
                                       const char* pkg_id,
                                       app_path_type_t app_path_type,
                                       char*** ppp_paths);

/**
 * Remove path and all rules associated with it from the database.
 *
 * This does not remove data from the filesystem.
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] pkg_id application identifier
 * \param[in] path path to remove
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_remove_path(ss_transaction *transaction,
                                         const char* pkg_id,
                                         const char *path);

/**
 * Make two applications "friends", by giving them both full permissions on
 * each other.
 * Results will be persistent on the file system. Must be called after
 * security_server_perm_app_enable_permissions() has been called for each application.
 * It must be called by privileged user.
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] pkg_id1 application identifier
 * \param[in] pkg_id2 application identifier
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_add_friend(ss_transaction *transaction,
                                        const char* pkg_id1,
                                        const char* pkg_id2);

/**
 * Adds new permission (api feature) to the database.
 * It must be called within database transaction started with
 * security_server_perm_begin() and finished with security_server_perm_end().
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] app_type application type
 * \param[in] api_feature_name name of newly added permission (api feature)
 * \param[in] tizen_version string representing tizen version.
 * \param[in] smack_rules set of rules granted by the permission - NULL terminated
 *            list of NULL terminated rules.
 * \param[in] fast informs not to delete old rules during redefining permission.
 *                 it makes it run faster, but be caution using this durig
 *                 api-feature redefinition: not all rules will be deleted.
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_define_permission(ss_transaction *transaction,
                                           app_type_t app_type,
                                           const char* api_feature_name,
                                           const char* tizen_version,
                                           const char** smack_rules,
                                           bool fast);

/**
 * Adds additional rules to the database. The rules can use wild-cards and labels.
 * It must be called within database transaction started with security_server_perm_begin() and
 * finished with security_server_perm_commit().
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] set_smack_rule_set set_smack_rule_set  an array of rules, NULL terminated
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_add_additional_rules(ss_transaction *transaction,
                                              const char** set_smack_rule_set);

/**
 * Set privilege version for specific app. This function has to be
 * called before assigning any privileges, otherwise incorrect versions
 * of privileges will be assigned. If this function is not called,
 * default privilege version is the current tizen version. The provided
 * version has to be available in smack-privilege-config package, that
 * is installed on the target device, otherwise that version is not
 * supported.
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] s_app_label_nam application's label name
 * \param[in] s_version version to set
 *
 * \return SECURITY_SERVER_API_SUCCESS on success,
 *         SECURITY_SERVER_API_ERROR_INPUT_PARAM on unsupported version
 *         or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_set_privilege_version(ss_transaction *transaction,
                                                   const char* const s_app_label_name,
                                                   const char * const s_version);

/**
 * Get privilege version for specific app.
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] s_app_label_name application's label name
 * \param[out] p_version return version - this should be freed
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_get_privilege_version(ss_transaction *transaction,
                                                   const char* const s_app_label_name,
                                                   char **p_version);

/**
 * Allows selected blacklisted permissions to be used by given application.
 * Applications won't be  able to use blacklisted permission when they are
 * disabled and they are disabled by default. Passing permission name that
 * is not on a black list will result in an error.
 *
 * It must within database transaction started with security_server_perm_begin()
 * and finished with security_server_perm_commit().
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] s_app_label_name application identifier
 * \param[in] perm_type permission type
 * \param[in] pp_perm_list array of blacklist permission names. Supports both
 *            url format (http://tizen.org/permission/...)
 *            and file format (org.tizen.permission...).
 *            Last element must be NULL.
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_enable_blacklist_permissions(ss_transaction *transaction,
                                                          const char* const s_app_label_name,
                                                          app_type_t perm_type,
                                                          const char** pp_perm_list);

/**
 * Disables selected blacklisted permissions for given application. This
 * setting overrides permissions requested by app during installation as well
 * as permissions enabled with security_server_perm_app_enable_permissions().
 * Passing permission name that is not on a black list or is not enabled
 * will result in an error.
 *
 * It must be called within database transaction started with security_server_perm_begin()
 *  and finished with security_server_perm_commit().
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] s_app_label_name application identifier
 * \param[in] perm_type permission type
 * \param[in] pp_perm_list array of blacklist permission names. Supports both
 *            url format (http://tizen.org/permission/...)
 *            and file format (org.tizen.permission...). Last
 *            element must be NULL.
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_disable_blacklist_permissions(ss_transaction *transaction,
                                                           const char* const s_app_label_name,
                                                           app_type_t perm_type,
                                                           const char** pp_perm_list);

/**
 * Returns a list of black list permissions and their status (enabled/disabled)
 * for given app.
 *
 * \param[in] transaction Security server permission transaction
 * \param[in] s_app_label_name application identifier
 * \param[out] pp_perm_list placeholder of array of blacklist permission structures containing
 *                          permission name and its status. Returned
 *                          permissions are in url format
 *                          (http://tizen.org/permission/...) Free it with
 *                          perm_free_blacklist_statuses(...)
 * \param[out] p_perm_number placeholder for size of the blacklist permission array
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_app_get_blacklist_statuses(ss_transaction *transaction,
                                                    const char* const s_app_label_name,
                                                    perm_blacklist_status_t** pp_perm_list,
                                                    size_t* p_perm_number);

/**
 * Free the list of blacklist statuses allocated with
 * security_server_perm_app_get_blacklist_statuses(...).
 *
 * \param[in] p_perm_list array of blacklist permission structures containing
 *            i_perm_number permission name and its status.
 * \param[in] size of the blacklist permission array
 */
void security_server_perm_free_blacklist_statuses(perm_blacklist_status_t* p_perm_list,
                                                  size_t i_perm_number);

/**
 * Perform a configuration refresh on a rule database.
 *
 *
 * File names in given directory are checked to match permission file format
 * "PREFIX_apiFeatureName.smack" (PREFIX has to match application type
 * (WRT_, EFL_, OSP_, etc). If the filename matches the format, proper permission
 * will be reloaded from file: rules defined in files will replace rules in database.
 *
 * If subdirectory of given directory has name that matches format "%d.%d.%d", e.g.
 * "2.2.0", then files from that subdirectory will be also read and loaded to database
 * as if they were privileges of tizen in version matching subdirectory name.
 * if directory is set to NULL, the standard directory ("/usr/share/privilege-control/")
 * is taken as parameter.
 * If parameter clear_not_found_permissions is set to 1, all privileges' SMACK rules
 * that are not described in one of files found in given directory will be cleared.
 * The entries for privileges' names and versions and applciation's privileges will be
 * left in database, but the privilege-rule mapping will be cleared for every privilege
 * not found on dir.
 * If set to 0, there will be no additional changes on database except updating of
 * found privileges's rules.
 *
 * It must be called by privileged user.
 *
 * \param[in] dir directory's path, from which information will be read.
 * \param[in] clear_not_found_permissions input flag for indicating need of additional
 *            resetting of all privileges
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_db_configuration_refresh(const char *const dir,
                                                  int clear_not_found_permissions);

/**
 * Apply sharing between owner and receiver on given list of paths. If s_owner_pkg_id is not the
 * real owner of all paths in pp_path_list, sharing will fail.
 *
 * \param[in] transaction          Security server permission transaction, when NULL function will
 *                                 create transaction by itself
 * \param[in]  path_list        list of path strings to share. Last element should be NULL.
 * \param[in]  owner_pkg_id        package id of application owning paths
 * \param[in]  receiver_pkg_id     package id of application the paths will be shared with
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_apply_sharing(ss_transaction *transaction,
                                       const char **path_list,
                                       const char *owner_pkg_id,
                                       const char *receiver_pkg_id);

/**
 * Drop sharing between owner and receiver on given list of paths. If s_owner_pkg_id is not the
 * real owner of all paths in pp_path_list, sharing will fail.
 *
 * \param[in] transaction          Security server permission transaction, when NULL function will
 *                                 create transaction by itself
 * \param[in]  path_list           list of path strings to share. Last element should be NULL.
 * \param[in]  owner_pkg_id        package id of application owning paths
 * \param[in]  receiver_pkg_id     package id of application the paths was shared with
 *
 * \return SECURITY_SERVER_API_SUCCESS on success or error code on fail
 *
 * Access to this function requires SMACK rule: "<app_label> security-server::api-permissions w"
 */
int security_server_perm_drop_sharing(ss_transaction *transaction,
                                      const char **path_list,
                                      const char *owner_pkg_id,
                                      const char *receiver_pkg_id);
#ifdef __cplusplus
}
#endif

#endif // SECURITY_SERVER_PERM_H
