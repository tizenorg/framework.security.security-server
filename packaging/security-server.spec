Name:       security-server
Summary:    Security server and utilities
Version:    0.0.132
Release:    1
Group:      System/Security
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires: cmake
BuildRequires: libcap-devel
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: libattr-devel
BuildRequires: pkgconfig(libiri)
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(libsystemd-daemon)
BuildRequires: pkgconfig(sqlite3)
BuildRequires: pkgconfig(vasum)
Requires:	smack-privilege-config
%{?systemd_requires}

%description
Security server and utilities

%package -n libsecurity-server-client
Summary:    Security server (client)
Group:      Development/Libraries
Requires:   security-server = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libsecurity-server-client
Security server package (client)

%package -n libsecurity-server-client-devel
Summary:    Security server (client-devel)
Group:      Development/Libraries
Requires:   libsecurity-server-client = %{version}-%{release}

%description -n libsecurity-server-client-devel
Security server package (client-devel)

%package -n security-server-devel
Summary:    for web applications (Development)
Group:      Development/Libraries
Requires:   security-server = %{version}-%{release}

%description -n security-server-devel
Security daemon for web applications (Development)

%package -n security-server-certs
Summary:    Certificates for web applications.
Group:      Development/Libraries
Requires:   security-server

%description -n security-server-certs
Certificates for wrt.

%package -n libprivilege-control-conf
Summary:    Control privilege of application files
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
Requires:   /usr/bin/chsmack
Provides:   libprivilege-control-conf

%description -n libprivilege-control-conf
Configuration files and scripts to control privilege of application files

%prep
%setup -q

%build
%if "%{?tizen_profile_name}" == "wearable"
        __PROFILE_TYPE="WEARABLE"
%else
%if "%{?tizen_profile_name}" == "mobile"
        __PROFILE_TYPE="MOBILE"
%else
%if "%{?tizen_profile_name}" == "tv"
        __PROFILE_TYPE="TV"
%endif
%endif
%endif

%if "%{_repository}" == "emulator"
        __REPOSITORY="EMULATOR"
%else
	__REPOSITORY="NON_EMUL"
%endif

export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
export LDFLAGS+="-Wl,--rpath=%{_libdir}"

%cmake . -DVERSION=%{version} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
        -DCMAKE_VERBOSE_MAKEFILE=ON \
        -DTIZEN_ZONE_ENABLED:BOOL=ON \
        -DPROFILE_TYPE="${__PROFILE_TYPE}" \
        -DREPOSITORY="${__REPOSITORY}" \
        %{?seccomp_enabled:-DSECCOMP_ENABLED=ON}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/libsecurity-server-client
mkdir -p %{buildroot}/etc/security/
cp security-server-audit.conf %{buildroot}/etc/security/
mkdir -p %{buildroot}/usr/share/security-server/
cp label-whitelist %{buildroot}/usr/share/security-server/
cp label-blacklist %{buildroot}/usr/share/security-server/
%make_install

mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
mkdir -p %{buildroot}/usr/lib/systemd/system/sockets.target.wants
mkdir -p %{buildroot}/usr/lib/systemd/system/basic.target.wants
ln -s ../security-server.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/security-server.service
ln -s ../security-server-data-share.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-data-share.socket
ln -s ../security-server-get-gid.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-get-gid.socket
ln -s ../security-server-privilege-by-pid.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-privilege-by-pid.socket
ln -s ../security-server-app-permissions.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-app-permissions.socket
ln -s ../security-server-permissions.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-permissions.socket
ln -s ../security-server-cookie-get.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-cookie-get.socket
ln -s ../security-server-cookie-check.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-cookie-check.socket
ln -s ../security-server-app-privilege-by-name.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-app-privilege-by-name.socket
ln -s ../security-server-open-for-privileged.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-open-for-privileged.socket
ln -s ../security-server-open-for-unprivileged.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-open-for-unprivileged.socket
ln -s ../security-server-password-check.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-password-check.socket
ln -s ../security-server-password-set.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-password-set.socket
ln -s ../security-server-password-reset.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-password-reset.socket
ln -s ../security-server-label.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-label.socket
ln -s ../smack-rules.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/smack-rules.service
ln -s ../smack-default-labeling.service %{buildroot}/usr/lib/systemd/system/basic.target.wants/smack-default-labeling.service

mkdir -p %{buildroot}/smack
mkdir -p %{buildroot}/etc/smack-app/accesses.d
mkdir -p %{buildroot}/etc/smack-app-early/accesses.d
mkdir -p %{buildroot}/opt/dbspace
mkdir -p %{buildroot}/opt/data/privilege-control-cache

%clean
rm -rf %{buildroot}

%post
systemctl daemon-reload
if [ $1 = 1 ]; then
    # installation
    systemctl start security-server.service
fi

if [ $1 = 2 ]; then
    # update
    systemctl restart security-server.service
fi

if [ ! -d "/var/log/audit" ]; then
# Will enter here if audit directory doesn't exist
mkdir -p /var/log/audit
fi

#disabled by Kidong Kim in libprivilege-control patch: 5725c9a8
#touch /smack/load2

/usr/share/privilege-control/db/updater.sh

api_feature_loader --verbose --clear-permissions
api_feature_loader --verbose --rules=/usr/share/privilege-control/ADDITIONAL_RULES.smack

%check
./db/updater.sh --check-files %{buildroot}

%preun
if [ $1 = 0 ]; then
    # unistall
    systemctl stop security-server.service
fi

%postun
if [ $1 = 0 ]; then
    # unistall
    systemctl daemon-reload
fi

%post -n libsecurity-server-client -p /sbin/ldconfig

%postun -n libsecurity-server-client -p /sbin/ldconfig

%files -n security-server
%manifest %{_datadir}/security-server.manifest
%attr(755,root,root) /usr/bin/security-server
%attr(755,root,root) /usr/bin/api_feature_loader
%attr(755,root,root) /usr/bin/smack_rules_buffer
%attr(500,root,root) /usr/bin/load-rules.sh
%attr(755,root,root) /usr/bin/sharing_cleanup
%{_libdir}/libsecurity-server-commons.so.*
%{_libdir}/librules-db-sql-udf.so
%attr(-,root,root) /usr/lib/systemd/system/multi-user.target.wants/security-server.service
%attr(-,root,root) /usr/lib/systemd/system/security-server.service
%attr(-,root,root) /usr/lib/systemd/system/security-server.target
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-data-share.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-data-share.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-get-gid.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-get-gid.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-privilege-by-pid.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-privilege-by-pid.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-app-permissions.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-app-permissions.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-permissions.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-permissions.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-cookie-get.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-cookie-get.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-cookie-check.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-cookie-check.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-app-privilege-by-name.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-app-privilege-by-name.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-open-for-privileged.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-open-for-privileged.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-open-for-unprivileged.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-open-for-unprivileged.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-password-check.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-password-check.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-password-set.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-password-set.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-password-reset.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-password-reset.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-label.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-label.socket
%attr(-,root,root) /etc/security/security-server-audit.conf
%attr(-,root,root) /usr/share/security-server/label-whitelist
%attr(-,root,root) /usr/share/security-server/label-blacklist
%attr(-,root,root) /usr/lib/systemd/system/multi-user.target.wants/smack-rules.service
%attr(-,root,root) /usr/lib/systemd/system/smack-rules.service
# Except onlycap feature from tv profile
%if "%{?tizen_profile_name}" != "tv"
/usr/share/privilege-control/onlycap_list
%endif
/usr/share/privilege-control/db/rules-db.sql
/usr/share/privilege-control/db/rules-db-data.sql
/usr/share/privilege-control/db/updater.sh
/usr/share/privilege-control/db/updates/*.sql
/usr/share/privilege-control/db/load-rules-db.sql
/usr/share/privilege-control/db/remove-volatile-rules.sql
/etc/opt/upgrade/220.libprivilege-updater.patch.sh
%dir /smack
%dir /etc/smack-app/accesses.d
%dir /etc/smack-app-early/accesses.d
%attr(755, root, app) %dir /opt/dbspace
%attr(700, root, root) %dir /opt/data/privilege-control-cache

%{_datadir}/license/%{name}

%files -n libsecurity-server-client
%manifest %{_datadir}/libsecurity-server-client.manifest
%defattr(-,root,root,-)
%{_libdir}/libsecurity-server-client.so.*
%{_datadir}/license/libsecurity-server-client

%files -n libsecurity-server-client-devel
%defattr(-,root,root,-)
%{_libdir}/libsecurity-server-client.so
%{_libdir}/libsecurity-server-commons.so
/usr/include/security-server/security-server.h
/usr/include/security-server/security-server-error.h
/usr/include/security-server/security-server-perm.h
/usr/include/security-server/security-server-perm-types.h
/usr/include/security-server/security-server-plugin-api.h
%{_libdir}/pkgconfig/*.pc

%files -n libprivilege-control-conf
%manifest %{_datadir}/libprivilege-control-conf.manifest
%attr(755,root,root) /etc/rc.d/*
%attr(-,root,root) /usr/lib/systemd/system/smack-default-labeling.service
%attr(-,root,root) /usr/lib/systemd/system/basic.target.wants/smack-default-labeling.service
