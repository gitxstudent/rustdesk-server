Source: rustdesk-server
Section: net
Priority: optional
Maintainer: HuyMin <info@vnfap.com>
Build-Depends: debhelper (>= 10), pkg-config
Standards-Version: 4.5.0
Homepage: https://vnfap.com/

Package: rustdesk-server-hbbs
Architecture: {{ ARCH }}
Depends: systemd ${misc:Depends}
Description: VNFap server
 Self-host your own VNFap server, it is free and open source.

Package: rustdesk-server-hbbr
Architecture: {{ ARCH }}
Depends: systemd ${misc:Depends}
Description: VNFap server
 Self-host your own VNFap server, it is free and open source.
 This package contains the VNFap relay server.

Package: rustdesk-server-utils
Architecture: {{ ARCH }}
Depends: ${misc:Depends}
Description: VNFap server
 Self-host your own VNFap server, it is free and open source.
 This package contains the rustdesk-utils binary.
