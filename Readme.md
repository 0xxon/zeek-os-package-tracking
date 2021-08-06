# Zeek OS & package info detector

The goal of this script is to detect certain operating systems, mostly Linux and BSD-based, and the packages installed on said operating systems.

Information about the found operating systems as well as the packages that have been found are written to new log-files.

The information collected by this script is extracted from HTTP requests. This is possible since Linux/BSD systems download packages via unencrypted HTTP (the packages are signed and cannot be modified by an attacker in transit).

Current supported operating systems are:

* Debian
* Ubuntu
* FreeBSD
* CentOS based systems

Planned additions:

* Fedora
* OpenSUSE

Please note that this script has not seen significant amounts of testing; it is likely that it will miss hosts and possible that it will generate incorrect findings. Future versions of this script might change the log-file-format.

### Logs

This script generates two new logs, `os_info.log` and `package_info.log`. The former log-file contains information about operating systems, the second about packages.

Information in `os_info.log` is cached for one day on each worker node, by default (setting: `OSPTracking::os_tracking_interval`).

Example `os_info.log`:

```
#fields	ts	host	os	version	platform	request.user_agent	request.host	request.uri
#types	time	addr	string	string	string	string	string	string
1621264582.343810	207.154.248.206	FreeBSD	12.2-RELEASE-p1	-	freebsd-update (fetch, 12.2-RELEASE-p1)	update1.freebsd.org	/12.2-RELEASE/amd64/latest.ssl
1621263628.479609	2a03:b0c0:3:d0::13b7:9001	Ubuntu	hirsute	-	Debian APT-HTTP/1.3 (2.2.3) non-interactive	mirrors.digitalocean.com	/ubuntu/dists/hirsute-updates/InRelease
1621263629.074601	2a03:b0c0:3:d0::13b7:9001	Ubuntu	hirsute	amd64	Debian APT-HTTP/1.3 (2.2.3) non-interactive	security.ubuntu.com	/ubuntu/dists/hirsute-security/main/binary-amd64/by-hash/SHA256/1871aa091cb7002e9fa33443ff3097222648f1cbb9fd8426943b28bcb4e5eef5
```

Example `package_info.log`:

```
#fields	ts	host	os	os_version	platform	package	version	prev_version	request.user_agent	request.host	request.uri
#types	time	addr	string	string	string	string	string	string	string	string	string
1621264718.280198	207.154.248.206	FreeBSD	12	amd64	pkg	1.16.3	-	pkg/1.16.1	pkgmir.geo.freebsd.org	/FreeBSD:12:amd64/quarterly/All/pkg-1.16.3.txz
1621264721.407269	207.154.248.206	FreeBSD	12	amd64	git	2.31.1_1	-	pkg/1.16.3	pkgmir.geo.freebsd.org	/FreeBSD:12:amd64/quarterly/All/git-2.31.1_1.txz
1621264721.910978	207.154.248.206	FreeBSD	12	amd64	p5-CGI	4.51	-	pkg/1.16.3	pkgmir.geo.freebsd.org	/FreeBSD:12:amd64/quarterly/All/p5-CGI-4.51.txz
1621264721.943651	207.154.248.206	FreeBSD	12	amd64	p5-HTML-Parser	3.75	-	pkg/1.16.3	pkgmir.geo.freebsd.org	/FreeBSD:12:amd64/quarterly/All/p5-HTML-Parser-3.75.txz
1621263639.242450	2a03:b0c0:3:d0::13b7:9001	Ubuntu	-	amd64	linux-modules-5.11.0-17-generic	5.11.0-17.18	-	Debian APT-HTTP/1.3 (2.2.3) non-interactive	mirrors.digitalocean.com/ubuntu/pool/main/l/linux/linux-modules-5.11.0-17-generic_5.11.0-17.18_amd64.deb
1621263639.307801	2a03:b0c0:3:d0::13b7:9001	Ubuntu	-	amd64	linux-image-5.11.0-17-generic	5.11.0-17.18	-	Debian APT-HTTP/1.3 (2.2.3) non-interactive	mirrors.digitalocean.com/ubuntu/pool/main/l/linux-signed/linux-image-5.11.0-17-generic_5.11.0-17.18_amd64.deb
1621263639.434855	2a03:b0c0:3:d0::13b7:9001	Ubuntu	-	amd64	linux-virtual	5.11.0.17.18	-	Debian APT-HTTP/1.3 (2.2.3) non-interactive	mirrors.digitalocean.com	/ubuntu/pool/main/l/linux-meta/linux-virtual_5.11.0.17.18_amd64.deb
1621263639.493213	2a03:b0c0:3:d0::13b7:9001	Ubuntu	-	amd64	linux-image-virtual	5.11.0.17.18	-	Debian APT-HTTP/1.3 (2.2.3) non-interactive	mirrors.digitalocean.com	/ubuntu/pool/main/l/linux-meta/linux-image-virtual_5.11.0.17.18_amd64.deb
1621263639.648662	2a03:b0c0:3:d0::13b7:9001	Ubuntu	-	amd64	linux-headers-virtual	5.11.0.17.18	-	Debian APT-HTTP/1.3 (2.2.3) non-interactive	mirrors.digitalocean.com	/ubuntu/pool/main/l/linux-meta/linux-headers-virtual_5.11.0.17.18_amd64.deb
```

### Installation

Using zkg:

```
zkg install 0xxon/zeek-os-package-tracking
```

Manually:

Copy `os-package-tracking.zeek` into your `site` directory and `@load` it from `local.zeek`.

### Configuration

Configure the hosts that are tracked by changing the `OSPTracking::track_hosts` option. By default all hosts are tracked.

## Acknowledgements

This work was supported by the US National Science Foundation under grant [OAC-1642161](https://nsf.gov/awardsearch/showAward?AWD_ID=1642161&HistoricalAwards=false).
Any opinions, findings, and conclusions or recommendations
expressed in this material are those of the authors or origina-
tors, and do not necessarily reflect the views of the National
Science Foundation.

