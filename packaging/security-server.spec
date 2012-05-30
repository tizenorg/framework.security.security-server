Name:       security-server
Summary:    Security server
Version: 0.0.1
Release:    37
Group:      TO_BE/FILLED_IN
License:    Apache 2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: packaging/security-server.manifest 
BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  libattr-devel

%description
Security server package

%package -n libsecurity-server-client
Summary:    Security server (client)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
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


%prep
%setup -q

%build
cp %{SOURCE1001} .
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}


make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install


%post
mkdir -p /etc/rc.d/rc3.d
mkdir -p /etc/rc.d/rc5.d
ln -s /etc/rc.d/init.d/security-serverd /etc/rc.d/rc3.d/S25security-server
ln -s /etc/rc.d/init.d/security-serverd /etc/rc.d/rc5.d/S25security-server

%postun
rm -f /etc/rc.d/rc3.d/S25security-server
rm -f /etc/rc.d/rc5.d/S25security-server

%post -n libsecurity-server-client -p /sbin/ldconfig

%postun -n libsecurity-server-client -p /sbin/ldconfig


%files
%manifest security-server.manifest
%defattr(-,root,root,-)
/etc/rc.d/init.d/security-serverd
/usr/bin/security-server
/usr/bin/sec-svr-util
/usr/share/security-server/mw-list


%files -n libsecurity-server-client
%manifest security-server.manifest
%defattr(-,root,root,-)
/usr/lib/libsecurity-server-client.so.*

%files -n libsecurity-server-client-devel
%manifest security-server.manifest
%defattr(-,root,root,-)
/usr/lib/libsecurity-server-client.so
/usr/include/security-server/security-server.h
/usr/lib/pkgconfig/security-server.pc

