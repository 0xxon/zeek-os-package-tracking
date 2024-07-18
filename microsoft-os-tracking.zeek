@load policy/frameworks/software/windows-version-detection.zeek

module OSPTracking;

export {
}

event HTTP::log_http(rec: HTTP::Info) &priority=5
	{
	if ( rec?$host && rec?$user_agent
	    && /crl\.microsoft\.com/ in rec$host
	    && /Microsoft-CryptoAPI\// in rec$user_agent )
		{
		if ( rec$user_agent !in OS::crypto_api_mapping )
			{
			found_os(rec$id$orig_h, "WINDOWS", "Unknown CryptoAPI Version", "WINDOWS",
			    RequestInfo($ts=rec$ts, $user_agent=rec$user_agent,
			    $host=rec$host, $uri=rec$uri));
			}
		else
			{
			local result = OS::crypto_api_mapping[rec$user_agent];
			print fmt("WINDOWS result %s", result);

			local name = fmt("%s", result$name);

			if ( result$version?$addl )
				name += fmt("%s-%s", name, result$version$addl);

			found_os(rec$id$orig_h, name, fmt("%s.%s", result$version$major,
			    result$version$minor), "WINDOWS", RequestInfo(
			    $ts=rec$ts, $user_agent=rec$user_agent,
			    $host=rec$host, $uri=rec$uri));
			}
		}
	}
