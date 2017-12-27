# vim: sw=4:ts=4:et

Name:           softu2f-systemd-daemon
Version:        1.0
Release:        1%{?dist}
Summary:        System daemon for SoftU2F 

License:        MIT
URL:            https://github.com/danstiner/softu2f-linux
Source0:        softu2f.service
Source1:        softu2f.socket

%{?systemd_requires}
BuildRequires:  systemd
Requires:       softu2f-systemd-daemon-selinux

%description
A systemd daemon that provides a socket interface for unprivileged
users to create software-only U2F devices.

%prep

%build
rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT
cargo build --bin softu2f-systemd-daemon --release
cp ../target/release/softu2f-systemd-daemon %{_builddir}
strip %{_builddir}/softu2f-systemd-daemon

%install
install -d %{buildroot}%{_libexecdir}/softu2f
install -m 755 %{_builddir}/softu2f-systemd-daemon %{buildroot}%{_libexecdir}/softu2f/systemd-daemon
install -d %{buildroot}%{_unitdir}
install -m 644 %{SOURCE0} %{buildroot}%{_unitdir}/softu2f.service
install -m 644 %{SOURCE1} %{buildroot}%{_unitdir}/softu2f.socket
install -d %{buildroot}%{_prefix}/lib/systemd/system-preset
install -m 644 softu2f.preset %{buildroot}%{_prefix}/lib/systemd/system-preset/95-softu2f.preset
install -d %{buildroot}%{_tmpfilesdir}
install -m 644 softu2f-tmpfiles.conf %{buildroot}%{_tmpfilesdir}/softu2f.conf

%post
%systemd_post softu2f.service
%systemd_post softu2f.socket

%preun
%systemd_preun softu2f.service
%systemd_preun softu2f.socket

%postun
%systemd_postun_with_restart softu2f.service
%systemd_postun_with_restart softu2f.socket

%files
%defattr(-,root,root,-)
%{_libexecdir}/softu2f/systemd-daemon
%{_unitdir}/softu2f.service
%{_unitdir}/softu2f.socket
%{_prefix}/lib/systemd/system-preset/95-softu2f.preset
%{_tmpfilesdir}/softu2f.conf


%changelog
* Tue Nov 21 2017 YOUR NAME <YOUR@EMAILADDRESS> 1.0-1
- Initial version

