/*
 *  security-server
 *  Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/smack.h>

#include "security-server-cookie.h"

/* Delete useless cookie item *
 * then connect prev and next */
int free_cookie_item(cookie_list *cookie)
{
	if(cookie->path != NULL)
		free(cookie->path);
	if(cookie->permissions != NULL)
		free(cookie->permissions);
        if(cookie->smack_label != NULL)
                free(cookie->smack_label);
	if(cookie->prev != NULL)
		cookie->prev->next = cookie->next;
	if(cookie->next != NULL)
		cookie->next->prev = cookie->prev;
	free(cookie);
	cookie = NULL;
	return 0;
}

/* Cut the link of the current cookie item and connect previous link and next line *
 * That is remove a cookie item *
 * Returns next cookie item  if exist, NULL for no more cookie item */
cookie_list *delete_cookie_item(cookie_list *cookie)
{
	cookie_list *retval = NULL;
	if(cookie == NULL)
	{
		SEC_SVR_DBG("%s", "Cannot delete null cookie");
		return retval;
	}

	/* Reconnect cookie item */
	if(cookie->next != NULL)
	{
		cookie->prev->next = cookie->next;
		cookie->next->prev = cookie->prev;
		retval = cookie->next;
	}
	else
	{
		cookie->prev->next = NULL;
	}
	
	free_cookie_item(cookie);
	return retval;
}

cookie_list * garbage_collection(cookie_list *cookie)
{
	char path[17];
	cookie_list *retval = NULL;
	struct stat statbuf;
	int ret;

	while(cookie != NULL)
	{
		/* Skip default cookie */
		if(cookie->pid ==0)
			return cookie;

		/* Try to find the PID directory from proc fs */
		snprintf(path, sizeof(path), "/proc/%d", cookie->pid);
		path[16] = 0;
		ret = stat(path, &statbuf);
		if(ret != 0)
		{
			/* If it's not exist, delete the cookie */
			if(errno == ENOENT)
			{
				SEC_SVR_DBG("Garbage found. PID:%d, deleting...", cookie->pid);
				cookie = delete_cookie_item(cookie);
				continue;
			}
			else
			{
				/* Some error occurred */
				SEC_SVR_DBG("Error occurred on stat: errno = %d", errno);
				return cookie;
			}
		}
		else
		{
			/* This is not a garbage. returning */
			return cookie;
		}

		cookie = cookie->next;
	}
	return retval;
}

/* Search existing cookie from the cookie list for the client process *
 * At the same time, it collects garbage cookie which PID is no longer exist and delete them */
cookie_list *search_existing_cookie(int pid, const cookie_list *c_list)
{
	cookie_list *current =(cookie_list *)c_list, *cookie = NULL;
	char *cmdline = NULL, *debug_cmdline = NULL;

	/* Search from the list */
	while(current != NULL)
	{
		/* print_cookie(current);*/
		current = garbage_collection(current);
		if(current == NULL)
			break;

		/* PID must be same */
		if(current->pid == pid)
		{
			/* Found cookie for the pid. Check the cookie is reused by dirrent executable */
			/* Check the path of the process */
			cmdline = (char*)read_cmdline_from_proc(pid);
			if(cmdline == NULL)
			{
				SEC_SVR_DBG("%s", "cannot read cmdline");
				return NULL;
			}
			/* Check the path is different */
			if(strncmp(cmdline, current->path, current->path_len) != 0 || strlen(cmdline) != current->path_len)
			{
				SEC_SVR_DBG("pid [%d] has been reused by %s. deleting the old cookie.", pid, cmdline);
				debug_cmdline = malloc(current->path_len + 1);
				if(debug_cmdline == NULL)
				{
					SEC_SVR_DBG("%s", "out of memory error");
					return NULL;
				}
				strncpy(debug_cmdline, current->path, current->path_len);
				debug_cmdline[current->path_len] = 0;
				SEC_SVR_DBG("[%s] --> [%s]", cmdline, debug_cmdline);
				if(debug_cmdline != NULL)
				{
					free(debug_cmdline);
					debug_cmdline = NULL;
				}
				/* Okay. delete current cookie */
				current = delete_cookie_item(current);
				if(cmdline != NULL)
				{
					free(cmdline);
					cmdline = NULL;
				}
				continue;
			}
			else
			{
				SEC_SVR_DBG("%s", "cookie found");
				cookie = current;
			}

			if(cmdline != NULL)
			{
				free(cmdline);
				cmdline = NULL;
			}
		}
		current = current->next;
	}
	return cookie;
}

/* Search existing cookie from the cookie list for matching pid *
 * Default cookie (meaning PID 0) is not allowed in here */
cookie_list *search_cookie_from_pid(cookie_list *c_list, int pid)
{
	cookie_list *current = (cookie_list *)c_list, *retval = NULL;

	/* Search from the list */
	while(current != NULL)
	{
		/* print_cookie(current);*/
		/* PID must be same */
		current = garbage_collection(current);
		if(current == NULL)
			break;

		if(current->pid == pid)
		{
			SEC_SVR_DBG("%s", "cookie has been found");
			retval = current;
			goto finish;
		}
		current = current->next;
	}
finish:
	return retval;
}

/* Search existing cookie from the cookie list for matching cookie and privilege */
/* If privilege is 0, just search cookie exists or not */
cookie_list *search_cookie(const cookie_list *c_list, const unsigned char *cookie, int privilege)
{
	cookie_list *current = (cookie_list *)c_list, *retval = NULL;
	int i;

	/* Search from the list */
	while(current != NULL)
	{
		/* print_cookie(current);*/
		/* PID must be same */
		current = garbage_collection(current);
		if(current == NULL)
			break;

		if(memcmp(current->cookie, cookie, SECURITY_SERVER_COOKIE_LEN) == 0)
		{
			SEC_SVR_DBG("%s", "cookie has been found");

			/* default cookie is for root process which is pid is set to 0 */
			if(current->pid == 0 || privilege == 0)
			{
				retval = current;
				goto finish;
			}
			else
			{
				for(i=0 ; i < current->permission_len ; i++)
				{
					if(privilege == current->permissions[i])
					{
						SEC_SVR_DBG("Found privilege %d", privilege);
						retval = current;
						goto finish;
					}
				}
			}
		}
		current = current->next;
	}
finish:
	return retval;
}


cookie_list *search_cookie_new(const cookie_list *c_list,
                               const unsigned char *cookie,
                               const char *object,
                               const char *access_rights)
{
	cookie_list *current = (cookie_list *)c_list, *retval = NULL;
        int ret;
	int i;

	/* Search from the list */
	while(current != NULL)
	{
		/* print_cookie(current);*/
		/* PID must be same */
		current = garbage_collection(current);
		if(current == NULL)
			break;

		if(memcmp(current->cookie, cookie, SECURITY_SERVER_COOKIE_LEN) == 0)
		{
			SEC_SVR_DBG("%s", "cookie has been found");

                                ret = smack_have_access(current->smack_label, object, access_rights);
          SEC_SVR_DBG("smack_have_access, subject >%s< object >%s< access >%s< ===> %d",
                    current->smack_label, object, access_rights, ret);
                                if (ret == 1)
                                {
                                        retval = current;
                                        goto finish;
                                }
		}
		current = current->next;
	}
finish:
	return retval;
}


/* Generage a random stream value of size to cookie *
 * by reading /dev/uranddom file */
int generate_random_cookie(unsigned char *cookie, int size)
{
	int fd, ret;

		fd = open("/dev/urandom", O_RDONLY);
		if(fd < 0)
		{
			SEC_SVR_DBG("%s", "Cannot open /dev/urandom");
			return SECURITY_SERVER_ERROR_FILE_OPERATION;
		}
		ret = read(fd, cookie, size);
		if(ret < size)
		{
			SEC_SVR_DBG("Cannot read /dev/urandom: %d", ret);
			ret = SECURITY_SERVER_ERROR_FILE_OPERATION;
			goto error;
		}
		close(fd);
		ret = SECURITY_SERVER_SUCCESS;
error:
	if(fd > 0)
		close(fd);
	return ret;
}

/* Create a cookie item from PID */
cookie_list *create_cookie_item(int pid, int sockfd, cookie_list *c_list)
{
	int ret, tempint;
	cookie_list *added = NULL, *current = NULL;
	char path[24], *cmdline = NULL;
	char *buf = NULL, inputed, *tempptr = NULL;
	char delim[] = ": ", *token = NULL;
	int *permissions = NULL, perm_num = 1, cnt, i, *tempperm = NULL;
        char *smack_label = NULL;
	FILE *fp = NULL;

	current = search_existing_cookie(pid, c_list);
	if(current != NULL)
	{
		/* There is a cookie for this process already */
		added = current;
		SEC_SVR_DBG("%s", "Existing cookie found");
		goto error;
	}

	/* Read command line of the PID from proc fs */
	cmdline = (char *)read_cmdline_from_proc(pid);
	if(cmdline == NULL)
	{
		SEC_SVR_DBG("Error on reading /proc/%d/cmdline", pid);
		goto error;
	}

	/*
	 * modified by security part
	 *  - get gid from /etc/group
	 */
	/* Read group info of the PID from proc fs - /proc/[PID]/status */
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	fp = fopen(path, "r");

	/* Find the line which starts with 'Groups:' */
	i = 0;
	
	while(1)
	{
		buf = (char*)malloc(sizeof(char) * 128);
		if(buf == NULL)
		{
			SEC_SVR_DBG("%s", "Error on malloc()");
			goto error;
		}
		memset(buf, 0x00, 128);
		cnt = 128;

		/* get one line from /proc/[PID]/status */
		while(1)
		{
			tempint = fgetc(fp);
			inputed = (char)tempint;
			if(tempint == EOF)
				goto out_of_while;
			else if(inputed == '\n')
			{
				buf[i] = '\0';
				break;
			}
			else if((i == cnt) && (inputed != '\n'))
			{
				tempptr = (char*)realloc(buf, sizeof(char) * (i + 128));
				if(tempptr == NULL)
				{
					SEC_SVR_DBG("%s", "Error on realloc()");
					goto error;
				}
				buf = tempptr;
				buf[i++] = inputed;
				cnt = i + 128;
			}
			else
				buf[i++] = inputed;
		}
		i = 0;

		/* find 'Groups:' */
		if(strncmp(buf, "Groups:", 7) == 0)
		{
			/* get gid from the line and insert to 'permissions' array */
			token = strtok(buf, delim); // first string is "Groups"
			while((token = strtok(NULL, delim)))
			{
				tempperm = realloc(permissions, sizeof(int) * perm_num);
				if(tempperm == NULL)
				{
					SEC_SVR_DBG("%s", "Error on realloc()");
					goto error;
				}
				permissions = tempperm;
				errno = 0;
				permissions[perm_num - 1] = strtoul(token, 0, 10);
				if (errno != 0)
				{
					SEC_SVR_DBG("cannot change string to integer [%s]", token);
					ret = SECURITY_SERVER_ERROR_SERVER_ERROR;
					goto error;
				}
				perm_num++;
			}
			perm_num--;

			/* goto out of while loop */
			break;
		}
		if(buf != NULL)
		{
			free(buf);
			buf = NULL;
		}
	}
out_of_while:
		
	/* Each group ID is stored in each line of the file */
//	while(fgets(permline, sizeof(permline), fp) != NULL)
//	{
//		permissions = realloc(permissions, sizeof(int) * perm_num);
//		if(permissions == NULL)
//		{
//			SEC_SVR_DBG("%s", "Error on realloc()");
//			goto error;
//		}
//		permissions[perm_num -1] = strtoul(permline, 0, 10);
//		perm_num++;
//	}
//	perm_num--;
	/*
	 * modifying end
	 */

	/* Go to last cookie from the list */
	current = c_list;
	while(current->next != NULL)
	{
		current = current->next;
	}

	/* Create a new one and assign values */
	added = malloc(sizeof(cookie_list));
	if(added == NULL)
		goto error;

	ret = generate_random_cookie(added->cookie, SECURITY_SERVER_COOKIE_LEN);
	if(ret != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("Error on making random cookie: %d", ret);
		free(added);
		added = NULL;
		goto error;
	}

        /* Check SMACK label */
        ret = smack_new_label_from_socket(sockfd, &smack_label);
        if (ret != 0)
	{
		SEC_SVR_DBG("Error checking peer label: %d", ret);
		free(added);
		added = NULL;
		goto error;
	}

	added->path_len = strlen(cmdline);
	added->path = calloc(1, strlen(cmdline));
	memcpy(added->path, cmdline, strlen(cmdline));

	added->permission_len = perm_num;
	added->pid = pid;
	added->permissions = permissions;
	added->smack_label = smack_label;
	added->prev = current;
	current->next = added;
	added->next = NULL;

error:
	if(cmdline != NULL)
		free(cmdline);
	if(fp != NULL)
		fclose(fp);
	if(buf != NULL)
		free(buf);

	if(added == NULL && permissions != NULL)
		free(permissions);

	return added;
}

/* Check stored default cookie, if it's not exist make a new one and store it */
int check_stored_cookie(unsigned char *cookie, int size)
{
	int fd, ret;

	/* First, check the default cookie is stored */
	fd = open(SECURITY_SERVER_DEFAULT_COOKIE_PATH, O_RDONLY);
	if(fd < 0)
	{
		if(errno != ENOENT)
		{
			SEC_SVR_DBG("Cannot open default cookie. errno=%d", errno);
			ret = SECURITY_SERVER_ERROR_FILE_OPERATION;
			unlink(SECURITY_SERVER_DEFAULT_COOKIE_PATH);
		}

		ret = generate_random_cookie(cookie, size);

		/* Save cookie to disk */
		fd = open(SECURITY_SERVER_DEFAULT_COOKIE_PATH, O_WRONLY | O_CREAT, 0600);
		if (fd < 0)
		{
			SEC_SVR_DBG("Cannot open default cookie errno=%d", errno);
			ret = SECURITY_SERVER_ERROR_FILE_OPERATION;
			goto error;
		}
		ret = write(fd, cookie, size);
		if(ret < size)
		{
			SEC_SVR_DBG("%s", "Cannot save default cookie");
			ret = SECURITY_SERVER_ERROR_FILE_OPERATION;
			goto error;
		}

		/* Change mod only allow root process to read */
		ret = fchmod(fd, 0600);
		if (ret < 0)
		{
			SEC_SVR_DBG("%s", "Cannot chmod default cookie");
			ret = SECURITY_SERVER_ERROR_FILE_OPERATION;
			goto error;
		}
		close(fd);
		return SECURITY_SERVER_SUCCESS;
	}

	ret = read (fd, cookie, size);
	if(ret < size)
	{
		SEC_SVR_DBG("Cannot read default cookie errno=%d", errno);
		ret = SECURITY_SERVER_ERROR_FILE_OPERATION;
		goto error;
	}
	ret = SECURITY_SERVER_SUCCESS;

error:
	if(fd > 0)
		close(fd);
	return ret;
}
/* Create a cookie item from PID */

/* Create a default cookie when security server is executed *
 * Default cookie is for root processes that needs cookie */
cookie_list *create_default_cookie(void)
{
	cookie_list *first = NULL;
	int ret;

	first = malloc(sizeof(cookie_list));

	ret = check_stored_cookie(first->cookie, SECURITY_SERVER_COOKIE_LEN);
	if(ret != SECURITY_SERVER_SUCCESS)
	{
		SEC_SVR_DBG("Error on making random cookie: %d", ret);
		free(first);
		return NULL;
	}

	first->path_len = 0;
	first->permission_len = 0;
	first->pid = 0;
	first->path = NULL;
	first->permissions = NULL;
        first->smack_label = NULL;
	first->prev = NULL;
	first->next = NULL;
	return first;
}
