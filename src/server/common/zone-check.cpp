#include <zone-check.h>
#include <dpl/log/log.h>
#include <string.h>

#ifndef ZONE_ENABLED
#else
#include <vasum.h>
#include <fstream>
#include <sys/socket.h>
#endif

namespace SecurityServer {

const std::string LXCPATH = "/var/lib/lxc";

int zone_declare_link(const std::string &hostPath, const std::string &zonePath)
{
#ifndef ZONE_ENABLED
    return 0;
#else
    vsm_context_h ctx;
    int ret = 1;

    ctx = vsm_create_context();
    if (NULL == ctx) {
        LogError("Failed to connect zone controller");
        return 1;
    }

    ret = vsm_declare_link(ctx, hostPath.c_str(), zonePath.c_str());
    vsm_cleanup_context(ctx);

    return ret;
#endif
}

void zone_get_default_zone(std::string &zoneName)
{
#ifndef ZONE_ENABLED
    zoneName = "host";
    return ;
#else
    zoneName = VSM_DEFAULT_ZONE;
    return ;
#endif
}

void zone_get_path_from_zone(const std::string &path, const std::string &zoneName,
                             std::string &zonePath)
{
#ifndef ZONE_ENABLED
    zonePath = path;
    return ;
#else
    if (strcmp(zoneName.c_str(), VSM_DEFAULT_ZONE) == 0)
        zonePath = path;
    else
        zonePath = LXCPATH + "/" + zoneName + "/rootfs" + path;
    return ;
#endif
}

bool zone_check_validity_name(const std::string &zoneName)
{
#ifndef ZONE_ENABLED
    return false;
#else
    vsm_context_h ctx;
    vsm_zone_h zone;
    bool ret = false;

    ctx = vsm_create_context();
    if (NULL == ctx) {
        LogError("Failed to connect zone controller");
        return false;
    }

    zone = vsm_lookup_zone_by_name(ctx, zoneName.c_str());
    if( zone != NULL)
        ret = true;
    else
        ret = false;

    vsm_cleanup_context(ctx);
    return ret;
#endif
}

int lookup_zone_by_pid(int pid, std::string &zoneName)
{
#ifndef ZONE_ENABLED
    zoneName = "host";
    return 0;
#else
    std::string path("/proc/" + std::to_string(pid) + "/cpuset");
    if(access(path.c_str(), F_OK)!= 0) {
        zoneName = "host";
        return 0;
    }

    std::ifstream file(path.c_str());
    std::string zoneInfo;
    getline(file, zoneInfo);
    file.close();

    if (zoneInfo.compare("/") == 0) {
        zoneName = "host";
        return 0;
    }

    if (zoneInfo.length() > 5) {
        zoneName = zoneInfo.substr(5);
        return 0;
    }
    LogError("Failed to lookup zone name form pid");

    return 1;
#endif
}

int lookup_zone_by_sockfd(int sockfd, std::string &zoneName)
{
#ifndef ZONE_ENABLED
    zoneName = "host";
    return 0;
#else
    struct ucred cr;
    socklen_t len = sizeof(struct ucred);
	if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &len))
	{
		LogError("getsockopt() failed");
		return 1;
	}

    return lookup_zone_by_pid(cr.pid, zoneName);
#endif
}

int zone_pid_has_cap(const std::string &zoneName, pid_t pid, cap_value_t cap, cap_flag_t flag)
{
#ifndef ZONE_ENABLED
    return -1;
#else
    int ret = -1;
    int cap_pid = 0;
    std::string path(LXCPATH + "/" + zoneName + "/rootfs/proc/" + std::to_string(pid) + "/status");
    std::string flagstr;
    std::string capstr;
    std::ifstream file(path.c_str());

    if (flag == CAP_EFFECTIVE)
        flagstr = "CapEff:\t";
    else if (flag == CAP_INHERITABLE)
        flagstr = "CapInh:\t";
    else if (flag == CAP_PERMITTED)
        flagstr = "CapPrm:\t";

    for (std::string line; getline(file, line); ) {
        if (strstr(line.c_str(), flagstr.c_str()) == line.c_str()) {
            if (cap < 32) {
                capstr = line.c_str() + flagstr.size() + 8;
            } else {
                capstr = line.c_str() + flagstr.size();
                cap -= 32;
            }
            for (int i = 0; i < 8; i++) {
                cap_pid *= 16;
                if (capstr[i] >= '0' && capstr[i] <= '9') {
                    cap_pid += capstr[i] - '0';
                } else {
                    cap_pid += capstr[i] - 'a' + 10;
                }
            }

            if (cap_pid & (1 << cap))
                return 1;
            else
                return 0;
        }
    }
    file.close();

    return ret;
#endif
}
} // namespace SecurityServer

