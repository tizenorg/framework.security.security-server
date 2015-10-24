#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <security-server.h>
#include <client-common.h>

#define DEVICE_SEC_POLICY	"/etc/device-sec-policy"

SECURITY_SERVER_API
int security_server_check_domain_name(const char* name)
{
	int ret = SECURITY_SERVER_API_SUCCESS; // success
	int i;
	FILE* fp = NULL;
	char buf[256] = {0, };
	char tmp[256] = {0, };
	char *s = NULL;

	if(!name) // name is null
		return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

	if(!(fp = fopen(DEVICE_SEC_POLICY, "r")))
		return SECURITY_SERVER_API_ERROR_FILE_OPEN_FAILED;

	while(fgets(buf, 256, fp)) {
		i = 0;
		if(!(s = strstr(buf, "ac_domain name"))) // ac_domain is not found
			continue;
		s += 16;
		
		while(s[i] != '"')
			i++;
		strncpy(tmp, s, i);
		tmp[i] = '\0';

		if(!(ret = strcmp(name, tmp))) // match
			break;
		else
			ret = SECURITY_SERVER_API_ERROR_NOT_EXIST_IN_DOMAIN_LIST;
	}

	fclose(fp);
	return ret;
}

