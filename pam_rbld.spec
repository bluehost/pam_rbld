Name:           pam_rbld
Summary:        A PAM (Pluggable Authentication Module) that is able to interact with RBLD
Group:          System Environment/Base
Version:        1.0
Release:        1%{?dist}
Distribution:   CentOS6
License:        GPLv2
Source0:        %{name}-%{version}.tar.gz
URL:            https://github.com/bluehost/pam_rbld
Packager:       %{packager}
Vendor:         %{vendor}
BuildRequires:  pam-devel
Requires:       pam

BuildRoot:    %{_tmppath}/%{name}-%{version}-build

%description
A PAM (Pluggable Authentication Module) that is able to interact with RBLD.

%prep
%setup -q

%build
CFLAGS="$RPM_OPT_FLAGS"
export CFLAGS

make

%install
rm -rf %{buildroot}
make -C $RPM_BUILD_DIR/%{name}-%{version} \
        DESTDIR=$RPM_BUILD_ROOT \
        install

mkdir -p $RPM_BUILD_ROOT/%{_datadir}/pam_rbld
cp -a COPYING $RPM_BUILD_ROOT/%{_datadir}/pam_rbld/COPYING

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(0755, root, root, -)
/lib64/security/pam_rbld.so
%{_datadir}/pam_rbld/COPYING

%changelog
* Tue Jan 21 2014 Erick Cantwell <ecantwell@bluehost.com> 1.0
- Changed code so that snprintf size for buffer is dynamic
- instead of hardcoded to 256.
- Added GPLv2 License
- Since this has been in production for a long time, bumping
- release to 1.0

* Wed Sep 25 2013 Erick Cantwell <ecantwell@bluehost.com> 0.5.1
- Changed logging so that list queried shows in the AUTH log

* Thu Sep 12 2013 Erick Cantwell <ecantwell@bluehost.com> 0.5
- Initial RPM build
