Name: pam_ssh
Version: 1.92
Release: 0.fdr.1
Epoch: 0
Summary: A Pluggable Authentication Module (PAM) for use with SSH.
Source: http://belnet.dl.sourceforge.net/sourceforge/%{name}/%{name}-%{version}.tar.bz2
URL: http://sourceforge.net/projects/pam-ssh/

License: BSD
BuildRoot:  %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: pam, openssh, openssh-clients
BuildRequires: pam-devel
Group: System Environment/Base

%description
This PAM module provides single sign-on behavior for UNIX using SSH. Users
are authenticated by decrypting their SSH private keys with the password
provided (probably to XDM). In the PAM session phase, an ssh-agent process is
started and keys are added.

%prep
%setup -q

%build
%configure
make clean
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
#%find_lang %{name}

find $RPM_BUILD_ROOT -type f -name "*.la" -exec rm -f {} ';'

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc AUTHORS NEWS README ChangeLog TODO
/%{_lib}/security/pam_ssh.so
%{_mandir}/man[^3]/pam_ssh*

%changelog
* Mon Mar 15 2004 Patrice Dumas <pertusus@free.fr> 0:1.9-0.fdr.1
- Use fedora-newrpmspec to update the spec file

* Fri Aug 16 2002 Dumas Patrice <dumas@centre-cired.fr>
- Initial build.
