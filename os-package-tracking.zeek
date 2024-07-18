# The goal of this script is to detect operating systems and packages installed on said operating systems.
# This script specifically focusses on unix-like systems that use package managers. At the moment this mostly
# encompasses a range of linux distributions, as well as FreeBSD systems.

module OSPTracking;

export {
	redef enum Log::ID += { OS_Log, Package_Log };

	global os_log_policy: Log::PolicyHook;
	global package_log_policy: Log::PolicyHook;

	## The categoty of hosts of which you would like to track the likely operating systems and packages that they
	## download.
	## Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS
	option track_hosts = ALL_HOSTS;

	## Duration for which per-host operating system information is stored and used for de-duplication on worker nodes.
	const os_tracking_interval = 1day;

	type RequestInfo: record {
		ts: time &default=network_time();
		user_agent: string &optional &log;
		host: string &optional &log;
		uri: string &optional &log;
	};

	type OSInfo: record {
		ts: time &log &default=network_time();
		host: addr &log;
		os: string &log;
		version: string &log &optional;
		platform: string &log &optional;
		request: RequestInfo &log &default=RequestInfo();
	};

	type PackageInfo: record {
		ts: time &log &default=network_time();
		host: addr &log;
		os: string &log &optional;
		os_version: string &log &optional;
		platform: string &log &optional;
		package: string &log;
		version: string &log;
		prev_version: string &log &optional;
		request: RequestInfo &log;
	};
}

global known_os: set[addr, string, string, string] &create_expire=os_tracking_interval;

event zeek_init() &priority=5
	{
	Log::create_stream(OSPTracking::OS_Log, [$columns=OSInfo, $path="os_info", $policy=os_log_policy]);
	Log::create_stream(OSPTracking::Package_Log, [$columns=PackageInfo, $path="package_info", $policy=package_log_policy]);
	}

function found_os(orig: addr, name: string, version: string, platform: string, r: RequestInfo)
	{
	if ( [orig, name, version, platform] in known_os )
		return;

	# TODO: cluster-aware deduping...
	local osi = OSInfo($ts=r$ts, $host=orig, $os=name, $request=r);
	if ( version != "" )
		osi$version = version;
	if ( platform != "" )
		osi$platform = platform;
	Log::write(OSPTracking::OS_Log, osi);

	add known_os[orig, name, version, platform];
	}

type PackageVersion: record {
	name: string;
	version: string;
	platform: string &optional;
	invalid: bool &default=T;
};

#type PackageAndOsVersion: record {
#	p: PackageVersion;
#	o: OSInfo;
#};

function parse_freebsd_package_version(p: string): PackageVersion
	{
	local version = sub_bytes(find_last(p, /-.*/), 2, -1);
	local package = sub_bytes(p, 1, |p|-|version|-1);
	local v = PackageVersion($name=package, $version=version);
	if ( version != "" && package != "" )
		v$invalid = F;
	return v;
	}

function parse_debian_package_version(n: string): PackageVersion
	{
	local name = "";
	local version = "";
	# debian packages have the form: name_version_platform.deb
	# platform can be "any".
	# I have no idea if package names can contain "_"'s - but let's assume so.
	# TODO: Version may have information about the debian version - but doesn't have to

	local parts = find_all_ordered(n, /[^_]+/);
	local p = PackageVersion($name=name, $version=version);
	if ( |parts| >= 3 )
		{
		local platform = parts[|parts|-1];
		p$version = parts[|parts|-2];
		p$name = sub_bytes(n, 1, |n|-(2+|platform|+|p$version|));
		if ( platform != "all" )
			p$platform = platform;
		p$invalid = F;
		}

	#local o = OSInfo($host=0.0.0.0, $os="Debian");
	return p;
	}

function parse_rpm_package_version(n: string): PackageVersion
	{
	local name = "";
	local version = "";
	# rpm packages have the form: name-parts-version-parts.rpm.
	# The end might also contain the platform.
	local p = PackageVersion($name=name, $version=version);
	local parts = split_string1(n, /-[[:digit:]]/);
	if ( |parts| == 2 )
		{
		name = parts[0];
		version = sub_bytes(n, |parts[0]|+2, -1);
		p = PackageVersion($name=name, $version=version, $invalid=F);
		}
	return p;
	}


function found_package(orig: addr, o: OSInfo, p: PackageVersion, r: RequestInfo)
	{
	if ( p$invalid )
		return;

	local pi = PackageInfo($ts=r$ts, $host=orig, $package=p$name, $version=p$version, $request=r);
	if ( o?$os )
		pi$os = o$os;
	if ( o?$version )
		pi$os_version = o$version;
	if ( o?$platform )
		pi$platform = o$platform;
	if ( p?$platform )
		pi$platform = p$platform;
	Log::write(OSPTracking::Package_Log, pi);
	}

# For now - let's be a bit lazy and get the information we want out of the http logging event.
event HTTP::log_http(i: HTTP::Info)
	{

	local parts : string_vec;
	local platform = "";
	local pi : PackageVersion ;
	local osi : OSInfo ;
	local pos : int ;

	if ( ! ( i?$user_agent && i?$host && i?$uri ) )
		return;

	if ( ! addr_matches_host(i$id$orig_h, track_hosts) )
		return;

	local filename = "";
	if ( i?$uri )
		filename = sub_bytes(find_last(i$uri, /\/.*/), 2, -1);
	local req = RequestInfo($ts=i$ts, $user_agent=i$user_agent, $host=i$host, $uri=i$uri);

	if ( "Debian APT-HTTP" in i$user_agent )
		{
		# Debian and Ubuntu
		# If it is debian security - let's just grep the version and be done.
		if ( /^\/debian-security\// in i$uri )
			{
			parts = find_all_ordered(i$uri, /[^\/]+/);
			if ( |parts| > 3 && parts[1] == "dists" )
				{
				platform = "";
				if ( |parts| > 5 && /^binary-/ in parts[5] )
					platform = sub_bytes(parts[5],8, -1);
				found_os(i$id$orig_h, "Debian", parts[2], platform, RequestInfo($ts=i$ts, $user_agent=i$user_agent, $host=i$host, $uri=i$uri));
				}
			else if ( |parts| == 7 && parts[1] == "pool" && parts[2] == "updates" && /\.deb$/ in parts[6] )
				{
				pi = parse_debian_package_version(sub_bytes(parts[6], 1, |parts[6]|-4));
				osi = OSInfo($host=i$id$orig_h, $os="Debian", $request=req);
				if ( ! pi$invalid )
					found_package(i$id$orig_h, osi, pi, req);
				}
			}
		else if ( /^\/debian\// in i$uri )
			{
			parts = find_all_ordered(i$uri, /[^\/]+/);
			if ( |parts| == 6 && parts[1] == "pool" && /\.deb$/ in parts[5] )
				{
				pi = parse_debian_package_version(sub_bytes(parts[5], 1, |parts[5]|-4));
				osi = OSInfo($host=i$id$orig_h, $os="Debian", $request=req);
				if ( ! pi$invalid )
					found_package(i$id$orig_h, osi, pi, req);
				}
			}
		else if ( /^\/ubuntu\// in i$uri )
			{
			parts = find_all_ordered(i$uri, /[^\/]+/);
			if ( |parts| > 3 && parts[1] == "dists" && /-/ in parts[2] )
				{
				pos = find_str(parts[2], "-");
				platform = "";
				if ( |parts| > 5 && /^binary-/ in parts[4] )
					platform = sub_bytes(parts[4],8, -1);
				found_os(i$id$orig_h, "Ubuntu", sub_bytes(parts[2], 0, pos), platform, RequestInfo($ts=i$ts, $user_agent=i$user_agent, $host=i$host, $uri=i$uri));
				}
			if ( |parts| == 6 && parts[1] == "pool" && /\.deb$/ in parts[5] )
				{
				pi = parse_debian_package_version(sub_bytes(parts[5], 1, |parts[5]|-4));
				osi = OSInfo($host=i$id$orig_h, $os="Ubuntu", $request=req);
				if ( ! pi$invalid )
					found_package(i$id$orig_h, osi, pi, req);
				}
			}
		# First - let's just grep the package versionsa
		}
	# Fedora, by default, uses HTTPS.
	# A, rather weak, hint that fedora is used are DNS queries for wildcard.fedoraproject.org and mirrors.fedoraproject.org
	else if ( /^(freebsd-update|pkg\/)/ in i$user_agent )
		{
		# FreeBSD. We should be able to get the version from this. First - let's see if the user-agent is formatted the way we assume
		local freebsd_update_ua = /freebsd-update \(.*, .*\)/ in i$user_agent;
		if ( freebsd_update_ua )
			{
			# ok, let's try to extract the OS-version.
			local freebsd_version = find_last(i$user_agent, /,.*\)/);
			freebsd_version = sub_bytes(freebsd_version, 3, |freebsd_version|-3);
			# sadly, we can't really get any more from this - at least not on a casual glance. The files downloaded using freebsd-updates
			# just use random hashes as filenames.
			# TODO: We might be able to extract the platform here.
			found_os(i$id$orig_h, "FreeBSD", freebsd_version, "", RequestInfo($ts=i$ts, $user_agent=i$user_agent, $host=i$host, $uri=i$uri));
			}

		# let's be rather simple here - and just check if the file-name ends in .txz
		if ( /\.txz$/ in filename )
			{
			# this means we have the package
			local package = sub_bytes(filename, 0, |filename|-4);
			if ( package == "packagesite" )
				# special - let's just skip this one
				package = "";


			if ( package != "" )
				{
				osi = OSInfo($host=i$id$orig_h, $os="FreeBSD", $request=req);
				local pv = parse_freebsd_package_version(package);

				if ( /^\/FreeBSD:/ in i$uri )
					{
					# I am not sure if there is a better way to get this information out of the string. Sometimes it would be really neat to have capturing regular
					# expressions...
					# It is just the slightest bit brittle
					local out = find_all_ordered(i$uri, /[^\/:]+/);
					if ( |out| > 3 )
						{
						osi$version=out[1];
						osi$platform=out[2];
						}
					}

				if ( ! pv$invalid )
					found_package(i$id$orig_h, osi, pv, req);
				}
			}

		# TODO: pkg also contains a bit of information about the OS-version. We should extract that
		}
	else if ( /^libdnf / in i$user_agent )
		{
		parts = find_all_ordered(sub_bytes(i$user_agent, 9, -1), /[^;)]+/);
		if ( |parts| == 3 && /Linux/ in parts[0] )
			{
			found_os(i$id$orig_h, parts[0], sub_bytes(parts[1], 2, -1), sub_bytes(parts[2], 2, -1), RequestInfo($ts=i$ts, $user_agent=i$user_agent, $host=i$host, $uri=i$uri));
			if ( /\.rpm$/ in i$uri )
				{
				local uriparts = find_all_ordered(i$uri, /[^\/]+/);
				pi = parse_rpm_package_version(sub_bytes(uriparts[|uriparts|-1], 1, |uriparts[|uriparts|-1]|-4));
				osi = OSInfo($host=i$id$orig_h, $os=parts[0], $platform=sub_bytes(parts[2], 2, -1), $request=req);
				if ( ! pi$invalid )
					found_package(i$id$orig_h, osi, pi, req);
				}
			}
		}
	}
