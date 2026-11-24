# SPDX-License-Identifier: MIT
#
# Packaged per the Fedora Rust Packaging Guidelines (cargo-rpm-macros).
# https://docs.fedoraproject.org/en-US/packaging-guidelines/Rust/
#
# Vendored dependencies: an exception, on purpose. rust-peerdup is built on
# p2panda, iroh and librqbit, and none of them (nor many of the crates
# they pull in) are packaged in Fedora, so the crates come from a vendor
# tarball made by packaging/vendor.sh. This is the guidelines' own vendoring
# path: %%cargo_prep -v, no %%cargo_generate_buildrequires, no -devel
# subpackage, and cargo-vendor.txt shipped so that every bundled crate gets
# a bundled(crate(NAME)) Provides. CONTRIBUTING.md, section 3, has the rest.

Name:           rust-peerdup
Version:        0.1.0
Release:        1%{?dist}
Summary:        Encrypted peer-to-peer folder sync daemon

# rust-peerdup itself is MIT. The rest is the licenses of the crates it is
# statically linked with (cargo-vendor.txt), as %%cargo_license_summary
# prints them in the build log. Update this when Cargo.lock changes.
License:        MIT
URL:            https://github.com/theronconrey/rust-peerdup
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
# Made by packaging/vendor.sh and attached to each GitHub release.
Source1:        %{url}/releases/download/v%{version}/%{name}-%{version}-vendor.tar.xz

ExclusiveArch:  %{rust_arches}

BuildRequires:  cargo-rpm-macros >= 26
BuildRequires:  systemd-rpm-macros
# Generates the man page from --help.
BuildRequires:  help2man
# native-tls (through reqwest) links the system OpenSSL, so TLS made that
# way follows the system crypto-policies.
BuildRequires:  pkgconfig(openssl)
# aws-lc-sys and ring (TLS for iroh's QUIC and rustls) compile C code.
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  cmake
BuildRequires:  clang

# The session bus, which starts the daemon on the first CLI call.
Requires:       dbus-common
Requires:       firewalld-filesystem
%{?systemd_requires}

%description
rust-peerdup keeps folders in sync between your machines without a central
server. Peers find each other and exchange metadata over p2panda gossip, move
file contents over BitTorrent with librqbit, and encrypt everything that
leaves the machine with per-share keys that rotate when a member is removed.

It runs as a per-user systemd service with a D-Bus API on the session bus;
the rust-peerdup command drives it.

%prep
%autosetup -n %{name}-%{version} -p1 -a1
%cargo_prep -v vendor

%build
%cargo_build
%{cargo_license_summary}
%{cargo_license} > LICENSE.dependencies
%cargo_vendor_manifest
help2man --no-info --no-discard-stderr \
    --name="encrypted peer-to-peer folder sync daemon" \
    --output=rust-peerdup.1 target/rpm/rust-peerdup

%install
%cargo_install
install -Dpm 0644 rust-peerdup.1 %{buildroot}%{_mandir}/man1/rust-peerdup.1
install -Dpm 0644 systemd/rust-peerdup.service \
    %{buildroot}%{_userunitdir}/rust-peerdup.service
install -Dpm 0644 dbus-1/org.peerdup.Daemon1.service \
    %{buildroot}%{_datadir}/dbus-1/services/org.peerdup.Daemon1.service
install -Dpm 0644 firewalld/rust-peerdup.xml \
    %{buildroot}%{_prefix}/lib/firewalld/services/rust-peerdup.xml

%check
%cargo_test

%post
%systemd_user_post rust-peerdup.service

%preun
%systemd_user_preun rust-peerdup.service

%postun
%systemd_user_postun_with_restart rust-peerdup.service

%files
%license LICENSE LICENSE.dependencies cargo-vendor.txt
%doc README.md CONTRIBUTING.md INTEGRATION_NOTES.md
%{_bindir}/rust-peerdup
%{_mandir}/man1/rust-peerdup.1*
%{_userunitdir}/rust-peerdup.service
%{_datadir}/dbus-1/services/org.peerdup.Daemon1.service
%{_prefix}/lib/firewalld/services/rust-peerdup.xml

%changelog
* Tue Nov 24 2026 Theron Conrey <theron@conrey.org> - 0.1.0-1
- Initial package
