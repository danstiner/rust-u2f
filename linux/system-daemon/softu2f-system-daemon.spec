# vim: sw=4:ts=4:et

Name:           softu2f-system-daemon
Version:        0.2.0
Release:        1%{?dist}
Summary:        System daemon for SoftU2F 

License:        MIT
URL:            https://github.com/danstiner/softu2f-linux
Source0:        softu2f.service
Source1:        softu2f.socket
Source2:        softu2f.preset

%{?systemd_requires}
BuildRequires:  systemd
Requires:       softu2f-system-daemon-selinux
Requires:       u2f-hidraw-policy

%description
A systemd daemon that provides a socket interface for unprivileged
users to create emulated U2F devices.

%prep

%build
rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT
cargo build --bin softu2f-system-daemon --release
cp ../target/release/softu2f-system-daemon %{_builddir}
strip %{_builddir}/softu2f-system-daemon

%install
install -d %{buildroot}%{_libexecdir}/softu2f
install -m 755 %{_builddir}/softu2f-system-daemon %{buildroot}%{_libexecdir}/softu2f/system-daemon
install -d %{buildroot}%{_unitdir}
install -m 644 %{SOURCE0} %{buildroot}%{_unitdir}/softu2f.service
install -m 644 %{SOURCE1} %{buildroot}%{_unitdir}/softu2f.socket
install -d %{buildroot}%{_prefix}/lib/systemd/system-preset
install -m 644 %{SOURCE2} %{buildroot}%{_prefix}/lib/systemd/system-preset/95-softu2f.preset
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
%{_libexecdir}/softu2f/system-daemon
%{_unitdir}/softu2f.service
%{_unitdir}/softu2f.socket
%{_prefix}/lib/systemd/system-preset/95-softu2f.preset
%{_tmpfilesdir}/softu2f.conf


%changelog
* Wed Dec 27 2017 Daniel Stiner <daniel.stiner@gmail.com> 1.0-1
- Initial version
