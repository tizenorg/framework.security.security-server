/*
 * libprivilege control
 *
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <fts.h>
#include <errno.h>
#include <math.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/smack.h>
#include <linux/capability.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <search.h>
#include <dirent.h>

#include "privilege-control.h"
#include "common.h"
#include "rules-db.h"

#define APP_GID	5000
#define APP_UID	5000
#define ADMIN_GROUP	6504
#define DEVELOPER_GID	5100
#define DEVELOPER_UID	5100
#define SYSTEM_UID	200
#define SYSTEM_GID	200

#define APP_USER_NAME	"app"
#define DEV_USER_NAME	"developer"
#define SYS_USER_NAME	"system"

#define APP_HOME_DIR	TOSTRING(HOMEDIR) "/app"
#define DEV_HOME_DIR	TOSTRING(HOMEDIR) "/developer"
#define SYS_HOME_DIR	TOSTRING(HOMEDIR) "/system"

#define APP_GROUP_PATH	"app_group_list"
#define DEV_GROUP_PATH	"dev_group_list"

#define SMACK_SRC_FILE_SUFFIX   "_src_file"
#define SMACK_SRC_DIR_SUFFIX    "_src_dir"
#define SMACK_DATA_SUFFIX       "_data"
#define WRT_BASE_DEVCAP         "WRT"

#ifdef PROFILE_TYPE_MOBILE
#define WRT_CLIENT_PATH1        "/usr/bin/wrt-client"
#define WRT_CLIENT_PATH2        "/usr/bin/WebProcess"

#elif PROFILE_TYPE_TV
#define WRT_CLIENT_PATH         "/usr/bin/wrt-client"
#define WRT_SERVICE_PATH        "/usr/bin/wrt-service"

#elif PROFILE_TYPE_WEARABLE
#define WRT_CLIENT_PATH         "/usr/bin/wrt-client"
#define WRT_SERVICE_PATH        "/usr/bin/wrt-service"
#endif

#define ACC_LEN                 6
#define TIZEN_PRIVILEGE_ANTIVIRUS  "http://tizen.org/privilege/antivirus"
#define TIZEN_PRIVILEGE_APPSETTING "http://tizen.org/privilege/appsetting"
#define PATH_RULES_PUBLIC_RO       "PATH_RULES_PUBLIC_RO.smack"
#define PATH_RULES_GROUP_RW        "PATH_RULES_GROUP_RW.smack"

typedef struct {
	char user_name[10];
	int uid;
	int gid;
	char home_dir[64];
	char group_list[64];
} new_user;

/**
 * Return values
 * <0 - error
 * 0 - skip
 * 1 - label
 */
typedef int (*label_decision_fn)(const FTSENT*);
enum {
	DECISION_SKIP = 0,
	DECISION_LABEL = 1
};

API int ss_perm_begin(void)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);
	return rdb_modification_start();
}

API int ss_perm_end(void)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	return rdb_modification_finish();
}

API int ss_perm_rollback(void)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	int ret = rdb_modification_rollback();

	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB %s failed with: %d", __func__, ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

/**
 * TODO: this function should be moved to libsmack in open-source.
 */
API int ss_get_smack_label_from_process(pid_t pid, char *smack_label)
{
	SECURE_C_LOGD("Entering function: %s. Params: pid=%i", __func__, pid);

	int ret;
	int fd AUTO_CLOSE;
	int PATH_MAX_LEN = 64;
	char path[PATH_MAX_LEN + 1];

	if (pid < 0) {
		C_LOGE("invalid param pid.");
		ret = PC_ERR_INVALID_PARAM;
		goto out;
	}

	if(smack_label == NULL) {
		C_LOGE("Invalid param smack_label (NULL).");
		ret = PC_ERR_INVALID_PARAM;
		goto out;
	}

	bzero(smack_label, SMACK_LABEL_LEN + 1);
	if (!have_smack()) { // If no smack just return success with empty label
		C_LOGD("No SMACK. Returning empty label");
		ret = PC_OPERATION_SUCCESS;
		goto out;
	}

	bzero(path, PATH_MAX_LEN + 1);
	
	ret = snprintf(path, PATH_MAX_LEN, "/proc/%d/attr/current", pid);
	if (ret == -1) {
		SECURE_C_LOGE("snprintf() failed: ", strerror(errno));
		ret = PC_ERR_INVALID_PARAM;
		goto out;
	}
	if (ret >= PATH_MAX_LEN) {
		SECURE_C_LOGE("File name exceeds maximum");
		ret = PC_ERR_INVALID_PARAM;
		goto out;
	}
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		SECURE_C_LOGE("Cannot open file %s (errno: %s)", path, strerror(errno));
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	ret = read(fd, smack_label, SMACK_LABEL_LEN);
	if (ret < 0) {
		SECURE_C_LOGE("Cannot read from file %s", path);
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	SECURE_C_LOGD("smack_label=%s", smack_label);

	ret = PC_OPERATION_SUCCESS;

out:
	return ret;
}

API int ss_smack_pid_have_access(pid_t pid,
				 const char* object,
				 const char *access_type)
{
	SECURE_C_LOGD("Entering function: %s. Params: pid=%i, object=%s, access_type=%s",
				__func__, pid, object, access_type);

	int ret;
	char pid_subject_label[SMACK_LABEL_LEN + 1];
	cap_t cap;
	cap_flag_value_t cap_v;

	if (!have_smack()) {
		C_LOGD("No SMACK. Return access granted");
		return 1;
	}

	if (pid < 0) {
		C_LOGE("Invalid pid.");
		return -1;
	}

	if(object == NULL) {
		C_LOGE("Invalid object param.");
		return -1;
	}

	if(access_type == NULL) {
		C_LOGE("Invalid access_type param");
		return -1;
	}

	//get SMACK label of process
	ret = ss_get_smack_label_from_process(pid, pid_subject_label);
	if (PC_OPERATION_SUCCESS != ret) {
		SECURE_C_LOGE("get_smack_label_from_process %d failed: %d", pid, ret);
		return -1;
	}
	SECURE_C_LOGD("pid %d has label: %s", pid, pid_subject_label);

	// do not call smack_have_access() if label is empty
	if (pid_subject_label[0] != '\0') {
		ret = smack_have_access(pid_subject_label, object, access_type);
		if ( -1 == ret) {
			C_LOGE("smack_have_access failed.");
			return -1;
		}
		if ( 1 == ret ) { // smack_have_access return 1 (access granted)
			C_LOGD("smack_have_access returned 1 (access granted)");
			return 1;
		}
	}

	// smack_have_access returned 0 (access denied). Now CAP_MAC_OVERRIDE should be checked
	C_LOGD("smack_have_access returned 0 (access denied)");
	cap = cap_get_pid(pid);
	if (cap == NULL) {
		C_LOGE("cap_get_pid failed");
		return -1;
	}
	ret = cap_get_flag(cap, CAP_MAC_OVERRIDE, CAP_EFFECTIVE, &cap_v);
	if (0 != ret) {
		C_LOGE("cap_get_flag failed");
		return -1;
	}

	if (cap_v == CAP_SET) {
		C_LOGD("pid %d has CAP_MAC_OVERRIDE", pid);
		return 1;

	} else {
		C_LOGD("pid %d doesn't have CAP_MAC_OVERRIDE", pid);
		return 0;
	}
}

static int label_all(const FTSENT* ftsent UNUSED)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	return DECISION_LABEL;
}

static int label_execs(const FTSENT* ftsent)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	C_LOGD("Mode = %d", ftsent->fts_statp->st_mode);
	// label only regular executable files
	if (S_ISREG(ftsent->fts_statp->st_mode) && (ftsent->fts_statp->st_mode & S_IXUSR))
		return DECISION_LABEL;
	return DECISION_SKIP;
}

static int label_dirs(const FTSENT* ftsent)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	// label only directories
	if (S_ISDIR(ftsent->fts_statp->st_mode))
		return DECISION_LABEL;
	return DECISION_SKIP;
}

static int label_links_to_execs(const FTSENT* ftsent)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	struct stat buf;
	char* target AUTO_FREE;

	// check if it's a link
	if ( !S_ISLNK(ftsent->fts_statp->st_mode))
		return DECISION_SKIP;

	target = realpath(ftsent->fts_path, NULL);
	if (!target) {
		SECURE_C_LOGE("Getting link target for %s failed (Error = %s)", ftsent->fts_path, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}
	if (-1 == stat(target, &buf)) {
		SECURE_C_LOGE("stat failed for %s (Error = %s", target, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}
	// skip if link target is not a regular executable file
	if (buf.st_mode != (buf.st_mode | S_IXUSR | S_IFREG)) {
		SECURE_C_LOGD("%s is not a regular executable file. Skipping.", target);
		return DECISION_SKIP;
	}

	return DECISION_LABEL;
}

static int dir_set_smack_r(const char *path, const char* label,
			   enum smack_label_type type, label_decision_fn fn)
{
	SECURE_C_LOGD("Entering function: %s. Params: path=%s, label=%s, type=%d",
				__func__, path, label, type);

	const char* path_argv[] = {path, NULL};
	FTS *fts AUTO_FTS_CLOSE;
	FTSENT *ftsent;
	int ret;

	fts = fts_open((char * const *) path_argv, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL) {
		C_LOGE("fts_open failed.");
		return PC_ERR_FILE_OPERATION;
	}

	while ((ftsent = fts_read(fts)) != NULL) {
		/* Check for error (FTS_ERR) or failed stat(2) (FTS_NS) */
		if (ftsent->fts_info == FTS_ERR || ftsent->fts_info == FTS_NS) {
			C_LOGE("FTS_ERR error or failed stat(2) (FTS_NS)");
			return PC_ERR_FILE_OPERATION;
		}

		ret = fn(ftsent);
		if (ret < 0) {
			C_LOGE("fn(ftsent) failed.");
			return ret;
		}

		if (ret == DECISION_LABEL) {
			C_LOGD("smack_lsetlabel (label: %s (type: %d), path: %s)", label, type, ftsent->fts_path);
			if (smack_lsetlabel(ftsent->fts_path, label, type) != 0) {
				C_LOGE("smack_lsetlabel failed.");
				return PC_ERR_FILE_OPERATION;
			}
		}
	}

	/* If last call to fts_read() set errno, we need to return error. */
	if (errno != 0) {
		C_LOGE("Last errno from fts_read: %s", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}
	return PC_OPERATION_SUCCESS;
}

API int ss_perm_app_enable_permissions(const char* pkg_id, app_type_t app_type,
				       const char** perm_list, bool persistent)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d, persistent=%d",
				__func__, pkg_id, app_type, persistent);
	int ret;
	const char *generated_pkg_id AUTO_FREE;
	generated_pkg_id = attach_label_prefix(pkg_id);

	if (!smack_label_is_valid(generated_pkg_id)) {
		C_LOGE("Invalid generated_pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	if (perm_list == NULL) {
		C_LOGE("Invalid perm_list (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	const char **tmp = perm_list;
	while (*tmp != NULL) {
		C_LOGD("\tpermission: %s\n", *tmp);
		tmp++;
	}

	if (app_type_group_name(app_type) == NULL) {
		C_LOGE("Unknown app type.");
		return PC_ERR_INVALID_PARAM;
	}

	/* Enable the permissions: */
	ret = rdb_enable_app_permissions(generated_pkg_id, app_type, perm_list,
					 !((bool)persistent));
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_enable_app_permissions failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int ss_perm_app_disable_permissions(const char* pkg_id, app_type_t app_type,
					const char** perm_list)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d",
				__func__, pkg_id, app_type);

	int ret;
	const char *generated_pkg_id AUTO_FREE;
	generated_pkg_id = attach_label_prefix(pkg_id);

	if (!smack_label_is_valid(generated_pkg_id)) {
		C_LOGE("Invalid generated_pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	if (perm_list == NULL) {
		C_LOGE("Invalid perm_list (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	if (app_type_group_name(app_type) == NULL) {
		C_LOGE("Unknown app type.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_disable_app_permissions(generated_pkg_id, app_type, perm_list);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_disable_app_permissions failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int ss_perm_app_revoke_permissions(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s", __func__, pkg_id);

	int ret;
	const char *generated_pkg_id AUTO_FREE;
	generated_pkg_id = attach_label_prefix(pkg_id);

	if (!smack_label_is_valid(generated_pkg_id)) {
		C_LOGE("Invalid generated_pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_revoke_app_permissions(generated_pkg_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_disable_app_permissions failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int ss_perm_app_reset_permissions(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);
	int ret;
	const char *generated_pkg_id AUTO_FREE;
	generated_pkg_id = attach_label_prefix(pkg_id);

	if (!smack_label_is_valid(generated_pkg_id)) {
		C_LOGE("Invalid generated_pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_reset_app_permissions(generated_pkg_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_disable_app_permissions failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int ss_perm_app_has_permission(const char *pkg_id,
				   app_type_t app_type,
				   const char *permission_name,
				   bool *is_enabled)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d, permission_name=%s",
				__func__, pkg_id, app_type, permission_name);

	const char *app_group = app_type_group_name(app_type);
	const char *generated_pkg_id AUTO_FREE;
	generated_pkg_id = attach_label_prefix(pkg_id);

	if (app_group == NULL) {
		C_LOGE("Unknown param app type.");
		return PC_ERR_INVALID_PARAM;
	}

	if (!smack_label_is_valid(generated_pkg_id)) {
		C_LOGE("Invalid generated_pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	if (permission_name == NULL) {
		C_LOGE("Invalid param permission_name (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	if (is_enabled == NULL) {
		C_LOGE("Invalid param is_enabled (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	return rdb_app_has_permission(generated_pkg_id, app_group, permission_name, is_enabled);
}

API int ss_perm_app_get_permissions(const char *pkg_id, app_type_t app_type, char ***ppp_perm_list)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d", __func__, pkg_id,
		      app_type);

	const char *app_group = app_type_group_name(app_type);
	int ret;
	const char *generated_pkg_id AUTO_FREE;
	generated_pkg_id = attach_label_prefix(pkg_id);

	if (ppp_perm_list == NULL) {
		C_LOGE("Invalid param ppp_perm_list (NULL).");
		return PC_ERR_INVALID_PARAM;
	}
	// Set the given pointer to NULL in case of future failure.
	*ppp_perm_list = NULL;

	if (app_group == NULL) {
		C_LOGE("Unknown param app type.");
		return PC_ERR_INVALID_PARAM;
	}

	if (!smack_label_is_valid(generated_pkg_id)) {
		C_LOGE("Invalid generated_pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_app_get_permissions(generated_pkg_id, app_group, ppp_perm_list);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_app_get_permissions failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int ss_perm_get_permissions(char ***ppp_permissions, app_type_t app_type)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d",
		      __func__, app_type);
	int ret;

	if(ppp_permissions == NULL) {
		C_LOGE("Invalid ppp_permissions (NULL).");
		return PC_ERR_INVALID_PARAM;
	}
	// Set the given pointer to NULL in case of future failure
	*ppp_permissions = NULL;

	const char *s_permission_type_name = app_type_group_name(app_type);

	if(s_permission_type_name == NULL) {
		C_LOGE("Unknown param app type.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_get_permissions(ppp_permissions, s_permission_type_name);

	if(ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB %s failed with: %d", __func__, ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int ss_perm_get_apps_with_permission(perm_app_status_t **pp_apps,
					 size_t *pi_apps_number,
					 app_type_t app_type,
					 const char *s_permission_name)
{
	SECURE_C_LOGD("Entering function: %s. Params: \
		       app_type=%d, s_permission_name=%s",
		       __func__, app_type, s_permission_name);
	int ret;

	if(pp_apps == NULL) {
		C_LOGE("Invalid ppp_permissions (NULL).");
		return PC_ERR_INVALID_PARAM;
	}
	// Set the given pointer to NULL in case of future failure
	*pp_apps = NULL;

	if(pi_apps_number == NULL) {
		C_LOGE("Invalid pi_apps_number (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	if(s_permission_name == NULL) {
		C_LOGE("Invalid s_permission_name (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	const char *s_permission_type_name = app_type_group_name(app_type);

	if(s_permission_type_name == NULL) {
		C_LOGE("Unknown param app type.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_get_apps_with_permission(pp_apps,
					   pi_apps_number,
					   s_permission_type_name,
					   s_permission_name);

	if(ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB %s failed with: %d", __func__, ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API void ss_perm_free_apps_list(perm_app_status_t *pp_apps,
				size_t i_apps_number)
{
	SECURE_C_LOGD("Entering function: %s. Params: i_apps_number=%d",
		      __func__, i_apps_number);

	size_t i;
	if(pp_apps != NULL) {
		for(i = 0; i < i_apps_number; ++i) {
			free(pp_apps[i].app_id);
		}
		free(pp_apps);
	}
}

static int app_label_dir(const char* label, const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: label=%s, path=%s",
				__func__, label, path);

	int ret = PC_OPERATION_SUCCESS;

	if(path == NULL) {
		C_LOGE("Invalid argument path (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	if (!smack_label_is_valid(label)) {
		C_LOGE("Invalid param label.");
		return PC_ERR_INVALID_PARAM;
	}

	//setting access label on everything in given directory and below
	ret = dir_set_smack_r(path, label, SMACK_LABEL_ACCESS, &label_all);
	if (PC_OPERATION_SUCCESS != ret)
	{
		C_LOGE("dir_set_smack_r failed.");
		return ret;
	}

	//setting execute label for everything with permission to execute
	ret = dir_set_smack_r(path, label, SMACK_LABEL_EXEC, &label_execs);
	if (PC_OPERATION_SUCCESS != ret)
	{
		C_LOGE("dir_set_smack_r failed.");
		return ret;
	}

	//setting execute label for everything with permission to execute
	ret = dir_set_smack_r(path, label, SMACK_LABEL_EXEC, &label_links_to_execs);
	return ret;
}

static int app_label_shared_dir(const char* app_label, const char* shared_label, const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_label=%s, shared_label=%s, path=%s",
				__func__, app_label, shared_label, path);
	int ret;

	if(path == NULL) {
		C_LOGE("Invalid param path.");
		return PC_ERR_INVALID_PARAM;
	}

	if(!smack_label_is_valid(app_label)) {
		C_LOGE("Invalid param app_label");
		return PC_ERR_INVALID_PARAM;
	}

	if(!smack_label_is_valid(shared_label)) {
		C_LOGE("Invalid param shared_label");
		return PC_ERR_INVALID_PARAM;
	}

	if (strcmp(app_label, shared_label) == 0) {
		C_LOGE("app_label equals shared_label");
		return PC_ERR_INVALID_PARAM;
	}

	//setting label on everything in given directory and below
	ret = dir_set_smack_r(path, shared_label, SMACK_LABEL_ACCESS, label_all);
	if(ret != PC_OPERATION_SUCCESS){
		C_LOGE("dir_set_smack_r failed.");
		return ret;
	}

	//setting transmute on dir
	ret = dir_set_smack_r(path, "1", SMACK_LABEL_TRANSMUTE, label_dirs);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("dir_set_smack_r failed");
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

static char* smack_label_for_path(const char *app_id, const char *path)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s, path=%s",
				__func__, app_id, path);

	char *salt AUTO_FREE;
	char *label;
	char *x;

	/* Prefix $1$ causes crypt() to use MD5 function */
	if (-1 == asprintf(&salt, "$1$%s", app_id)) {
		C_LOGE("asprintf failed");
		return NULL;
	}

	label = crypt(path, salt);
	if (label == NULL) {
		C_LOGE("crypt failed");
		return NULL;
	}

	/* crypt() output may contain slash character,
	 * which is not legal in Smack labels */
	for (x = label; *x; ++x) {
		if (*x == '/')
			*x = '%';
	}

	return label;
}

static char *attach_label_suffix(const char *label, const char *suffix)
{
	char *output = NULL;
	int ret;

	ret = asprintf(&output, "%s%s", label, suffix);
	if (ret == -1) {
		C_LOGE("asprintf failed");
		return NULL;
	}

	if (strlen(output) > SMACK_LABEL_LEN) {
		C_LOGE("Generated Smack label '%s' is too long", *output);
		free(output);
		return NULL;
	}

	C_LOGD("Generated label '%s'", *output);
	return output;
}

static int ss_perm_app_setup_path_internal(const char* pkg_id, const char* path,
					   app_path_type_t app_path_type, va_list ap)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, path=%s, app_path_type=%d",
				__func__, pkg_id, path, app_path_type);

	if(path == NULL) {
		C_LOGE("Invalid argument path.");
		return PC_ERR_INVALID_PARAM;
	}

	const char *generated_pkg_id AUTO_FREE;
	generated_pkg_id = attach_label_prefix(pkg_id);

	if (!smack_label_is_valid(generated_pkg_id)) {
		C_LOGE("Invalid generated_pkg_id.");
		SECURE_C_LOGE("Invalid generated_pkg_id %s", generated_pkg_id);
		return PC_ERR_INVALID_PARAM;
	}

	switch (app_path_type) {
	case APP_PATH_PRIVATE:
		C_LOGD("app_path_type is APP_PATH_PRIVATE.");
		return app_label_dir(generated_pkg_id, path);

	case APP_PATH_GROUP: {
		C_LOGD("app_path_type is APP_PATH_GROUP.");
		int ret;
		const char *shared_label;
		const char *gen_shared_label AUTO_FREE;

		shared_label = va_arg(ap, const char *);

		if (!smack_label_is_valid(shared_label)) {
			C_LOGE("Invalid shared_label.");
			return PC_ERR_INVALID_PARAM;
		}

		gen_shared_label = attach_label_prefix(shared_label);
		if (gen_shared_label == NULL) {
			C_LOGE("attach_label_prefix failed.");
			return PC_ERR_INVALID_OPERATION;
		}

		if (strcmp(generated_pkg_id, gen_shared_label) == 0) {
			C_LOGE("generated_pkg_id equals shared_label.");
			return PC_ERR_INVALID_PARAM;
		}

		ret = app_label_shared_dir(generated_pkg_id, gen_shared_label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("app_label_shared_dir failed: %d", ret);
			return ret;
		}

		// Add the path to the database:
		ret = rdb_add_path(generated_pkg_id, gen_shared_label, path, "rwxatl", "-", "GROUP_PATH");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("RDB rdb_add_path failed with: %d", ret);
			return ret;
		}

		return PC_OPERATION_SUCCESS;
	}

	case APP_PATH_PUBLIC: {
		C_LOGD("app_path_type is APP_PATH_PUBLIC.");
		const char *label;
		const char *gen_label AUTO_FREE;
		int ret;

		C_LOGD("New public RO path %s", path);

		// Generate label:
		label = smack_label_for_path(pkg_id, path);
		if (label == NULL) {
			C_LOGE("smack_label_for_path failed.");
			return PC_ERR_INVALID_OPERATION;
		}
		C_LOGD("Generated label '%s' for public RO path %s", label, path);

		gen_label = attach_label_prefix(label);
		if (gen_label == NULL) {
			C_LOGE("attach_label_prefix failed.");
			return PC_ERR_INVALID_OPERATION;
		}

		ret = app_label_shared_dir(generated_pkg_id, gen_label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("app_label_shared_dir failed.");
			return ret;
		}

		// Add the path to the database:
		ret = rdb_add_path(generated_pkg_id, gen_label, path, "rwxatl", "-", "PUBLIC_PATH");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("RDB rdb_add_path failed with: %d", ret);
			return ret;
		}

		return PC_OPERATION_SUCCESS;
	}

	case APP_PATH_SETTINGS: {
		C_LOGD("app_path_type is APP_PATH_SETTINGS.");
		const char *label;
		const char *gen_label AUTO_FREE;
		int ret;

		// Generate label:
		label = smack_label_for_path(pkg_id, path);
		if (label == NULL) {
			C_LOGE("smack_label_for_path failed.");
			return PC_ERR_INVALID_OPERATION;
		}
		C_LOGD("Appsetting: generated label '%s' for setting path %s", label, path);

		gen_label = attach_label_prefix(label);
		if (gen_label == NULL) {
			C_LOGE("attach_label_prefix failed.");
			return PC_ERR_INVALID_OPERATION;
		}

		/*set id for path and all subfolders*/
		ret = app_label_shared_dir(generated_pkg_id, gen_label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("Appsetting: app_label_shared_dir failed (%d)", ret);
			return ret;
		}

		// Add the path to the database:
		ret = rdb_add_path(generated_pkg_id, gen_label, path, "rwxatl", "-", "SETTINGS_PATH");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("RDB rdb_add_path failed with: %d", ret);
			return ret;
		}

		return PC_OPERATION_SUCCESS;
	}

	case PERM_APP_PATH_NPRUNTIME: {
		C_LOGD("app_path_type is PERM_APP_PATH_NPRUNTIME.");
		char *label AUTO_FREE;
		int ret;

		label = attach_label_suffix(generated_pkg_id, ".npruntime");
		if (label == NULL) {
			C_LOGE("creating npruntime label failed.");
			return PC_ERR_INVALID_OPERATION;
		}
		C_LOGD("Generated npruntime label '%s' for path %s", label, path);

		// Label executable/symlink
		ret = set_exec_label(label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("cannot set executable label '%s' for path %s.", label, path);
			return ret;
		}

		// Add the path to the database:
		ret = rdb_add_path(generated_pkg_id, label, path, "rw", "rwxat", "NPRUNTIME_PATH");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("RDB rdb_add_path failed with: %d", ret);
			return ret;
		}

		return PC_OPERATION_SUCCESS;
	}

	case APP_PATH_ANY_LABEL: {
		C_LOGD("app_path_type is APP_PATH_ANY_LABEL.");
		const char *label = NULL;
		label = va_arg(ap, const char *);
		return app_label_dir(label, path);
	}

	default:
		C_LOGE("app_path_type is invalid.");
		return PC_ERR_INVALID_PARAM;
	}

	return PC_OPERATION_SUCCESS;
}

API int ss_perm_app_setup_path(const char* pkg_id, const char* path, app_path_type_t app_path_type,
			       ...)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, path=%s, app_path_type=%d",
				__func__, pkg_id, path, app_path_type);

	va_list ap;
	int ret;
	va_start( ap, app_path_type );
	ret = ss_perm_app_setup_path_internal( pkg_id, path, app_path_type, ap );
	va_end( ap );
	return ret;
}

API int ss_perm_app_get_paths(const char* pkg_id, app_path_type_t app_path_type, char*** ppp_paths)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_path_type=%d", __func__,
		      pkg_id, app_path_type);

	const char *path_type_name = app_path_type_name(app_path_type);
	int ret;
	const char *generated_pkg_id AUTO_FREE;
	generated_pkg_id = attach_label_prefix(pkg_id);

	if (ppp_paths == NULL) {
		C_LOGE("Invalid param ppp_paths (NULL).");
		return PC_ERR_INVALID_PARAM;
	}
	// Set the given pointer to NULL in case of future failure.
	*ppp_paths = NULL;

	if (path_type_name == NULL) {
		C_LOGE("Unknown or invalid param app_path_type.");
		return PC_ERR_INVALID_PARAM;
	}

	if (!smack_label_is_valid(generated_pkg_id)) {
		C_LOGE("Invalid generated_pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_get_app_paths(generated_pkg_id, path_type_name, ppp_paths);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_app_get_paths failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int ss_perm_app_remove_path(const char* pkg_id, const char *path)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, path=%s", __func__, pkg_id, path);

	int ret;
	const char *generated_pkg_id AUTO_FREE;
	generated_pkg_id = attach_label_prefix(pkg_id);

	if (path == NULL) {
		C_LOGE("Invalid param path (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	if (!smack_label_is_valid(generated_pkg_id)) {
		C_LOGE("Invalid generated_pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_remove_path(generated_pkg_id, path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_remove_path failed with %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int ss_perm_app_add_friend(const char* pkg_id1, const char* pkg_id2)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id1=%s, pkg_id2=%s",
				__func__, pkg_id1, pkg_id2);

	int ret;
	const char *generated_pkg_id1 AUTO_FREE;
	const char *generated_pkg_id2 AUTO_FREE;

	if ((pkg_id1 == NULL) || (pkg_id2 == NULL)) {
		C_LOGE("Invalid pkg_id - cannot be NULL");
		return PC_ERR_INVALID_PARAM;
	}

	generated_pkg_id1 = attach_label_prefix(pkg_id1);
	generated_pkg_id2 = attach_label_prefix(pkg_id2);

	if ((!smack_label_is_valid(generated_pkg_id1)) ||
		(!smack_label_is_valid(generated_pkg_id2))) {
		C_LOGE("Invalid generated_pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_add_friend_entry(generated_pkg_id1, generated_pkg_id2);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_add_application failed with: %d", ret);
		return ret;
	}


	return PC_OPERATION_SUCCESS;
}

API int ss_perm_app_install(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);
	int ret;
	const char *generated_pkg_id AUTO_FREE;
	generated_pkg_id = attach_label_prefix(pkg_id);

	if (!smack_label_is_valid(generated_pkg_id)) {
		C_LOGE("Invalid generated_pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	// Add application to the database:
	ret = rdb_add_application(generated_pkg_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_add_application failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int ss_perm_app_uninstall(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s", __func__, pkg_id);
	int ret;
	const char *generated_pkg_id AUTO_FREE;
	generated_pkg_id = attach_label_prefix(pkg_id);

	if (!smack_label_is_valid(generated_pkg_id)) {
		C_LOGE("Invalid generated_pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	// Remove application from the database
	ret = rdb_remove_application(generated_pkg_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_remove_application failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int ss_perm_define_permission(app_type_t app_type,
				  const char* api_feature_name,
				  const char* tizen_version,
				  const char** smack_rules,
				  bool fast) {
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d, api_feature_name=%s, tizen_version=%s",
				__func__, app_type, api_feature_name, tizen_version);

	int ret = PC_OPERATION_SUCCESS;
	char *base_api_feature_name AUTO_FREE;
	const char *s_type_name = app_type_name(app_type);

	// Check input values
	if (s_type_name == NULL || !strcmp(s_type_name, "")) {
		C_LOGE("Unknown api type");
		return PC_ERR_INVALID_PARAM;
	}

	if (api_feature_name == NULL || strlen(api_feature_name) == 0) {
		C_LOGE("Api feature name is empty.");
		return PC_ERR_INVALID_PARAM;
	}

	if (smack_rules && ((ret = validate_all_rules(smack_rules) ) != PC_OPERATION_SUCCESS) ) {
		C_LOGE("Error in rules list.");
		return ret;
	}

	ret = base_name_from_perm(api_feature_name, &base_api_feature_name);
	if (ret != PC_OPERATION_SUCCESS){
		C_LOGE("Error during creating base name: ", ret);
		return ret;
	}

	// Save api feature to the database.
	ret = rdb_add_permission_rules(base_api_feature_name, tizen_version, s_type_name, smack_rules, fast);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_add_permission_rules failed with: %d", ret);
		return ret;
	}

	return ret;
}

API int ss_perm_add_additional_rules(const char** smack_rules){
	SECURE_C_LOGD("Entering function: %s.", __func__);
	int ret;
	if (!smack_rules){
		C_LOGE("smack_rules is NULL");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_add_additional_rules(smack_rules);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_add_additional_rules failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API const char* ss_perm_strerror(int errnum)
{
	switch (errnum) {
	case PC_OPERATION_SUCCESS:
		return "Success";
	case PC_ERR_FILE_OPERATION:
		return "File operation error";
	case PC_ERR_MEM_OPERATION:
		return "Memory operation error";
	case PC_ERR_NOT_PERMITTED:
		return "Operation not permitted";
	case PC_ERR_INVALID_PARAM:
		return "Invalid parameter";
	case PC_ERR_INVALID_OPERATION:
		return "Invalid operation";
	case PC_ERR_DB_OPERATION:
		return "Database operation error";
	case PC_ERR_DB_LABEL_TAKEN:
		return "Label taken by another application";
	case PC_ERR_DB_QUERY_PREP:
		return "Query failure during preparation";
	case PC_ERR_DB_QUERY_BIND:
		return "Query failure during binding";
	case PC_ERR_DB_QUERY_STEP:
		return "Query failure during stepping";
	case PC_ERR_DB_CONNECTION:
		return "Cannot establish a connection";
	case PC_ERR_DB_NO_SUCH_APP:
		return "No such application";
	case PC_ERR_DB_PERM_FORBIDDEN:
		return "Duplicate permission";
	default:
		return "Unknown error";
	}
}

API int ss_perm_app_set_privilege_version(const char* const s_app_label_name,
					  const char * const s_version)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);
	if (s_app_label_name == NULL)
	{
		C_LOGE("Error invalid parameter - application name cannot be null");
		return PC_ERR_INVALID_PARAM;
	};

	// Old apps with version <= 2.2.1 will use 2.2.1 privileges. 2.3, 2.3.1 and 2.4 remain unchanged.
#ifdef PROFILE_TYPE_MOBILE
	char* tmp_version = "2.2.1";
	if (NULL != s_version) {
		if (0 == strncmp(s_version,"2.3.1",5))
			tmp_version = "2.3.1";
		else if (0 == strncmp(s_version,"2.3",3))
			tmp_version = "2.3";
		else if (0 == strncmp(s_version,"2.4",3))
			tmp_version = "2.4";
	}
#elif PROFILE_TYPE_TV
	char* tmp_version = "2.3";
        if (NULL != s_version) {
                if (0 == strncmp(s_version,"2.4",3))
                        tmp_version = "2.4";
        }
#elif PROFILE_TYPE_WEARABLE
	char* tmp_version = "2.3";
        if (NULL != s_version) {
                if (0 == strncmp(s_version,"2.3.1",5))
                        tmp_version = "2.3.1";
                else if (0 == strncmp(s_version,"2.4",3))
                        tmp_version = "2.4";
        }
#endif

	int ret = rdb_is_version_available(tmp_version);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Version: %s is not available. Please install privileges for this version. Return value: %d", tmp_version, ret);
		return ret;
	}

	ret = rdb_set_app_version(s_app_label_name, tmp_version);
	if (ret != PC_OPERATION_SUCCESS)
	{
		C_LOGE("RDB rdb_set_app_version for application: %s failed with: %d", s_app_label_name, ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int ss_perm_app_get_privilege_version(const char* const s_app_label_name,
					  char **p_version)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);
	if (s_app_label_name == NULL)
	{
		C_LOGE("Error invalid parameter - application name cannot be null");
		return PC_ERR_INVALID_PARAM;
	};

	int ret;
	ret = rdb_get_app_version(s_app_label_name, p_version);
	if (ret != PC_OPERATION_SUCCESS)
	{
		C_LOGD(
				"RDB rdb_get_app_version for application: %s failed with: %d", s_app_label_name, ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
};

API int ss_perm_db_configuration_refresh(const char *const dir, int clear_not_found_permissions) {
	DIR *pdir;
	char *s_dir;
	struct dirent *ent;
	char *realp;
	int ret;
	if(clear_not_found_permissions) {
		C_LOGD("Clearing all permission rules\n");
		ret = rdb_remove_all_privileges_smack_rights();
		if (ret != PC_OPERATION_SUCCESS ) {
			C_LOGE("Clearing all permission rules failed!");
			return ret;
		}
		clear_cache_dir();
	}
	if(!dir)
		s_dir = "/usr/share/privilege-control/";
	else
		s_dir = (char *)dir;

	if (-1 == asprintf(&realp, "%s/%s", s_dir, "ADDITIONAL_RULES.smack"))
		C_LOGE("asprintf failed.");
	else {
		load_additional_rules(realp);
		free (realp);
	}

	C_LOGD("Loading permissions from '%s' as if they were for version of %s\n", s_dir, TIZEN_VERSION);
        load_from_dir(s_dir, TIZEN_VERSION, clear_not_found_permissions);
	if ((pdir = opendir(s_dir)) != NULL) {
		while ((ent = readdir(pdir)) != NULL) {

			if ((ent->d_type == DT_DIR || ent->d_type == DT_LNK) &&
				strcmp(".", ent->d_name) &&
				strcmp("..", ent->d_name) &&
				(NULL != strchr(ent->d_name, '.')))	// only directories with version names
			{
				if (-1 == asprintf(&realp, "%s/%s", s_dir, ent->d_name))
					C_LOGE("asprintf failed.");
				else {
					if (ent->d_type == DT_LNK) {
						char *temp = realpath(realp, NULL);
						if(!temp) {
							closedir (pdir);
							free(realp);
							return PC_ERR_FILE_OPERATION;
						}
						C_LOGD("Symbolic link %s points to %s\n", realp, temp);
						free(realp);
						realp = temp;
					}
					C_LOGD("Loading permissions from '%s' as if they were for version of %s\n", realp, ent->d_name);
					load_from_dir(realp, ent->d_name, clear_not_found_permissions);
					free (realp);
				}
			}
		}
		closedir (pdir);
	} else {
		C_LOGD("Opening directory %s failed: %m", s_dir );
		return PC_ERR_FILE_OPERATION;
	}
	return PC_OPERATION_SUCCESS;

}

static bool check_app_type(app_type_t perm_type) {
	return (perm_type <= PERM_APP_TYPE_LAST);
}

API int ss_perm_app_enable_blacklist_permissions(const char* const s_app_label_name,
						 app_type_t perm_type,
						 const char** pp_perm_list)
{
	if (!s_app_label_name || !check_app_type(perm_type) || !pp_perm_list || !(*pp_perm_list))
		return PC_ERR_INVALID_PARAM;

	return rdb_update_blacklist_permissions(s_app_label_name, perm_type, pp_perm_list, true);
}

API int ss_perm_app_disable_blacklist_permissions(const char* const s_app_label_name,
						  app_type_t perm_type,
						  const char** pp_perm_list)
{
	if (!s_app_label_name || !check_app_type(perm_type) || !pp_perm_list || !(*pp_perm_list))
		return PC_ERR_INVALID_PARAM;

	return rdb_update_blacklist_permissions(s_app_label_name, perm_type, pp_perm_list, false);
}

API int ss_perm_app_get_blacklist_statuses(const char* const s_app_label_name,
					   perm_blacklist_status_t** pp_perm_list,
					   size_t* p_perm_number)
{
	if (!s_app_label_name || !pp_perm_list || !p_perm_number)
		return PC_ERR_INVALID_PARAM;

	return rdb_get_blacklist_statuses(s_app_label_name, pp_perm_list, p_perm_number);
}

API void ss_perm_free_blacklist_statuses(perm_blacklist_status_t* p_perm_list,
					 size_t i_perm_number)
{
	size_t i;
	if (!p_perm_list || i_perm_number == 0)
		return;

	for (i = 0; i < i_perm_number; ++i)
		free(p_perm_list[i].permission_name);
	free(p_perm_list);
}

static bool is_path_owner(const char *s_path, const char *s_owner_label)
{
	char *path_label AUTO_FREE;
	if (smack_getlabel(s_path, &path_label, SMACK_LABEL_ACCESS) < 0) {
		C_LOGE("smack_getlabel failed.");
		return false;
	}

	// Check if it is private path
	if (strcmp(s_owner_label, path_label) == 0) {
		return true;
	}

	//Check if sharing was already applied
	char *generated_path_label AUTO_FREE;
	generated_path_label = attach_label_suffix(s_owner_label, "::shared");
	if (generated_path_label == NULL) {
		C_LOGE("attach_label_suffix failed.");
		return false;
	}

	if (strcmp(generated_path_label, path_label) == 0) {
		return true;
	}
	return false;
}

static int drop_sharing(const char *s_path, const char *s_owner_label, const char *s_target_label)
{
	struct smack_accesses *rules AUTO_SMACKFREE;
	char *path_label AUTO_FREE;
	if (smack_getlabel(s_path, &path_label, SMACK_LABEL_ACCESS) < 0) {
		C_LOGE("smack_getlabel failed.");
		return PC_ERR_INVALID_OPERATION;
	}

	const char *generated_path_label AUTO_FREE;
	generated_path_label = attach_label_suffix(s_owner_label, "::shared");
	if (generated_path_label == NULL) {
		C_LOGE("attach_label_suffix failed.");
		return PC_ERR_INVALID_OPERATION;
	}

	if (strcmp(generated_path_label, path_label)) {
		C_LOGE("Path isn't shared or app is not a real owner");
		return PC_ERR_INVALID_OPERATION;
	}

	int counter, path_sharing_count, owner_sharing_count, pair_sharing_count;
	int ret = rdb_get_sharing_count(s_owner_label, s_target_label, s_path, &counter);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("rdb_get_sharing_count failed with %d.", ret);
		return ret;
	}

	// No label or rule to change, only decrementing counter
	if (counter > 1) {
		C_LOGD("%s shares %s with %s more than on time.", s_owner_label, s_path,
		       s_target_label);
		goto db_remove;
	}

	ret = rdb_get_path_sharing_count(s_path, &path_sharing_count);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("rdb_get_path_sharing_count failed with %d.", ret);
		return ret;
	}

	ret = rdb_get_owner_sharing_count(s_owner_label, &owner_sharing_count);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("rdb_get_owner_sharing_count failed with %d.", ret);
		return ret;
	}

	ret = rdb_get_pair_sharing_count(s_owner_label, s_target_label, &pair_sharing_count);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("rdb_get_pair_sharing_count failed with %d.", ret);
		return ret;
	}

	// No label or rule to change, only remove record
	if (path_sharing_count > 1 && pair_sharing_count > 1) {
		goto db_remove;
	}

	// Relabel path if it isn't shared with any other app
	if (path_sharing_count <= 1 && smack_setlabel(s_path, s_owner_label, SMACK_LABEL_ACCESS)) {
		C_LOGE("smack_setlabel failed");
		return PC_ERR_INVALID_OPERATION;
	}

	if (smack_accesses_new(&rules)) {
		C_LOGE("smack_accesses_new failed");
		return PC_ERR_INVALID_OPERATION;
	}

	// Remove receiver access if it doesn't share any other path with owner app
	if (pair_sharing_count <= 1 && smack_accesses_add_modify(rules, s_target_label,
								 generated_path_label, "", "rl") < 0) {
		C_LOGE("smack_accesses_add_modify failed");
		return PC_ERR_INVALID_OPERATION;
	}

	if (smack_accesses_apply(rules)) {
		C_LOGE("smack_accesses_apply failed");
		return PC_ERR_INVALID_OPERATION;
	}

db_remove:
	ret = rdb_remove_sharing(s_owner_label, s_target_label, s_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("rdb_remove_sharing failed with %d.", ret);
		return ret;
	}

	ret = rdb_remove_path(s_owner_label, s_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("rdb_remove_path failed with %d", ret);
		return ret;
	}

	return ret;
}

API int ss_perm_apply_sharing(const char **pp_path_list, const char *s_owner_pkg_id,
                              const char *s_receiver_pkg_id)
{
	if (!pp_path_list || !s_owner_pkg_id || !s_receiver_pkg_id)
		return PC_ERR_INVALID_PARAM;

	char *generated_owner_label AUTO_FREE;
	generated_owner_label = attach_label_prefix(s_owner_pkg_id);
	if (generated_owner_label == NULL) {
		C_LOGE("attach_label_prefix failed.");
		return PC_ERR_INVALID_OPERATION;
	}

	int i, j;
	for (i = 0; pp_path_list[i]; i++) {
		if (!is_path_owner(pp_path_list[i], generated_owner_label)) {
			C_LOGE("Path '%s' is not owned by '%s'", pp_path_list[i], s_owner_pkg_id);
			return PC_ERR_INVALID_OPERATION;
		}
	}

	const char *generated_receiver_label AUTO_FREE;
	generated_receiver_label = attach_label_prefix(s_receiver_pkg_id);
	if (generated_receiver_label == NULL) {
		C_LOGE("attach_label_prefix failed.");
		return PC_ERR_INVALID_OPERATION;
	}

	const char *generated_path_label AUTO_FREE;
	generated_path_label = attach_label_suffix(generated_owner_label, "::shared");
	if (generated_path_label == NULL) {
		C_LOGE("attach_label_suffix failed.");
		return PC_ERR_INVALID_OPERATION;
	}

	struct smack_accesses *rules AUTO_SMACKFREE;
	if (smack_accesses_new(&rules)) {
		C_LOGE("smack_accesses_new failed");
		return PC_ERR_INVALID_OPERATION;
	}

	int ret = PC_ERR_INVALID_OPERATION;
	//Allow owner access
	if (smack_accesses_add_modify(rules, generated_owner_label, generated_path_label,
				      "rwxatl", "") < 0) {
		C_LOGE("smack_accesses_add_modify failed");
		goto fail;
	}

	//Allow receiver access
	if (smack_accesses_add_modify(rules, generated_receiver_label,
				      generated_path_label, "rl", "") < 0) {
		C_LOGE("smack_accesses_add_modify failed");
		goto fail;
	}

	//Allow traversing through owner directories
	if (smack_accesses_add_modify(rules, generated_receiver_label, generated_owner_label, "x", "") < 0) {
		C_LOGE("smack_accesses_add_modify failed");
		goto fail;
	}

	if (smack_accesses_apply(rules)) {
		C_LOGE("smack_accesses_apply failed");
		goto fail;
	}

	int properly_labeled = 0;
	for (i = 0; pp_path_list[i]; i++) {
		if (smack_setlabel(pp_path_list[i], generated_path_label, SMACK_LABEL_ACCESS)) {
			C_LOGE("smack_setlabel failed");
			goto fail;
		}
		properly_labeled++;

		ret = rdb_add_path(generated_owner_label, generated_path_label,
					"", "rwxat", "-", "SHARED_PATH");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("rdb_add_path failed with: %d", ret);
			goto fail;
		}

		ret = rdb_add_sharing(generated_owner_label, generated_receiver_label,
					  pp_path_list[i]);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("rdb_add_sharing failed with %d.", ret);
			goto fail;
		}
	}

	return PC_OPERATION_SUCCESS;
fail:
	//Undo path label change
	for (j = 0; j < properly_labeled && pp_path_list[j]; j++) {
		drop_sharing(pp_path_list[j], generated_owner_label, generated_receiver_label);
	}
	return ret;
}

API int ss_perm_drop_sharing(const char **pp_path_list, const char *s_owner_pkg_id,
                             const char *s_receiver_pkg_id)
{
	if (!pp_path_list || !s_owner_pkg_id || !s_receiver_pkg_id) {
		return PC_ERR_INVALID_PARAM;
	}

	const char *generated_owner_label AUTO_FREE;
	generated_owner_label = attach_label_prefix(s_owner_pkg_id);
	if (generated_owner_label == NULL) {
		C_LOGE("attach_label_prefix failed.");
		return PC_ERR_INVALID_OPERATION;
	}

	const char *generated_receiver_label AUTO_FREE;
	generated_receiver_label = attach_label_prefix(s_receiver_pkg_id);
	if (generated_receiver_label == NULL) {
		C_LOGE("attach_label_prefix failed.");
		return PC_ERR_INVALID_OPERATION;
	}

	int i;
	for (i = 0; pp_path_list[i]; i++) {
		int ret = drop_sharing(pp_path_list[i], generated_owner_label,
				       generated_receiver_label);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("drop_sharing failed with %d.", ret);
			return ret;
		}
	}

	return PC_OPERATION_SUCCESS;
}

static void process_sharing_clear(const char *s_owner_label, const char *s_target_label,
				  const char *s_path)
{
	(void)s_target_label;
	if (smack_setlabel(s_path, s_owner_label, SMACK_LABEL_ACCESS)) {
		C_LOGE("smack_setlabel failed for path %s and owner %s.", s_path, s_owner_label);
	}
}

API int ss_perm_clear_sharing(void) {
	int ret = rdb_process_sharing(process_sharing_clear);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("rdb_process_sharing failed with %d.", ret);
		return ret;
	}

	ret = rdb_clear_sharing();
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("rdb_clear_sharing failed with %d.", ret);
	}
	return ret;
}
