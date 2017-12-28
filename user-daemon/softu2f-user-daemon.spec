# vim: sw=4:ts=4:et

Name:           softu2f-user-daemon
Version:        0.1.0
Release:        1%{?dist}
Summary:        User daemon for SoftU2F

License:        MIT
URL:            https://github.com/danstiner/softu2f-linux
Source0:        softu2f.service
Source1:        softu2f.preset

%{?systemd_requires}
BuildRequires:  systemd
Requires:       softu2f-system-daemon

%description
A user daemon that creates a software-only U2F device. Relies on the service
softu2f-system-daemon being installed.

%prep

%build
rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT
cargo build --bin softu2f-user-daemon --release
cp ../target/release/softu2f-user-daemon %{_builddir}
strip %{_builddir}/softu2f-user-daemon

%install
install -d %{buildroot}%{_libexecdir}/softu2f
install -m 755 %{_builddir}/softu2f-user-daemon %{buildroot}%{_libexecdir}/softu2f/user-daemon
install -d %{buildroot}%{_userunitdir}
install -m 644 %{SOURCE0} %{buildroot}%{_userunitdir}/softu2f.service
install -d %{buildroot}%{_prefix}/lib/systemd/user-preset
install -m 644 %{SOURCE1} %{buildroot}%{_prefix}/lib/systemd/user-preset/95-softu2f.preset

%post
%systemd_user_post softu2f.service

%preun
%systemd_user_preun softu2f.service

%postun
%systemd_user_postun_with_restart softu2f.service

%files
%defattr(-,root,root,-)
%{_libexecdir}/softu2f/user-daemon
%{_userunitdir}/softu2f.service
%{_prefix}/lib/systemd/user-preset/95-softu2f.preset

%changelog
* Wed Dec 27 2017 Daniel Stiner <daniel.stiner@gmail.com> 1.0-1
- Initial version
