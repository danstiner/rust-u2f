# vim: sw=4:ts=4:et


%define relabel_files() \
restorecon -R /usr/libexec/softu2f/system-daemon; \

%define selinux_policyver 0.0.0

Name:   softu2f-system-daemon-selinux
Version:	0.1.0
Release:	1%{?dist}
Summary:	SELinux policy module for softu2f-system-daemon

Group:	System Environment/Base		
License:	GPLv2+	
URL:		https://github.com/danstiner/softu2f-linux
Source0:	softu2f-system-daemon.pp
Source1:	softu2f-system-daemon.if
Source2:	softu2f-system-daemon-selinux.8

Requires: policycoreutils, libselinux-utils
Requires(post): selinux-policy-base >= %{selinux_policyver}, policycoreutils
Requires(postun): policycoreutils
BuildArch: noarch

%description
This package installs and sets up the SELinux policy security module for softu2f-system-daemon.

%install
install -d %{buildroot}%{_datadir}/selinux/packages
install -m 644 %{SOURCE0} %{buildroot}%{_datadir}/selinux/packages
install -d %{buildroot}%{_datadir}/selinux/devel/include/contrib
install -m 644 %{SOURCE1} %{buildroot}%{_datadir}/selinux/devel/include/contrib/
install -d %{buildroot}%{_mandir}/man8/
install -m 644 %{SOURCE2} %{buildroot}%{_mandir}/man8/softu2f-system-daemon-selinux.8
install -d %{buildroot}/etc/selinux/targeted/contexts/users/

%post
semodule -n -i %{_datadir}/selinux/packages/softu2f-system-daemon.pp
if /usr/sbin/selinuxenabled ; then
    /usr/sbin/load_policy
    %relabel_files
fi;
exit 0

%postun
if [ $1 -eq 0 ]; then
    semodule -n -r softu2f-system-daemon
    if /usr/sbin/selinuxenabled ; then
       /usr/sbin/load_policy
       %relabel_files
    fi;
fi;
exit 0

%files
%attr(0600,root,root) %{_datadir}/selinux/packages/softu2f-system-daemon.pp
%{_datadir}/selinux/devel/include/contrib/softu2f-system-daemon.if
%{_mandir}/man8/softu2f-system-daemon-selinux.8.*

%changelog
* Wed Dec 27 2017 Daniel Stiner <daniel.stiner@gmail.com> 1.0-1
- Initial version

