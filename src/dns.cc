// ARES is *slow!* ADNS seems to be much faster, at least 10x

// Oops, I misunderstood wildcards. I'll probably just yank all the wildcard code.

#include <adns.h>

#include <iostream>
#include <climits>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <set>

#include <netdb.h>
#include <arpa/inet.h>

// Return all substrings of haystack that begin in needle. This is used for
// generating wildcard domains.
std::vector<std::string> all_substrs(const std::string & haystack,
	const std::string & needle) {

	std::vector<std::string> output;

	for (size_t i = haystack.find(needle, 0);
		 	i != std::string::npos && i < haystack.size();
			i = haystack.find(needle, i+1)) {

			output.push_back(haystack.substr(i));
		}

	return output;
}

// Should this contain a port so that each thread only accesses a particular
// host:port combination? I don't think that's necessary so far...
class resolved_host {
	private:
		// If possibly_IP is an IP address, set the resolved host to this IP and
		// return true, otherwise return false.
		bool import_ip(std::string possibly_IP);

	public:
		bool ipv6;
		in_addr ipv4_addr;
		in6_addr ipv6_addr;
		std::string rendered_ip() const;

		friend bool operator<(const resolved_host & lhs,
			const resolved_host & rhs) {

			return lhs.rendered_ip() < rhs.rendered_ip();
		}

		// If possibly_IP is an IP address, set the resolved host to this IP and
		// return true, otherwise return false.
		bool update_with_ip(std::string possibly_IP);
};

// Produce a human-readable rendering of the IP stored in this object
std::string resolved_host::rendered_ip() const {
	char ipbuf[INET6_ADDRSTRLEN];

	if (ipv6) {
		inet_ntop(AF_INET6, &ipv6_addr, ipbuf, sizeof(ipbuf));
	} else {
		inet_ntop(AF_INET, &ipv4_addr, ipbuf, sizeof(ipbuf));
	}

	return ipbuf;
}

bool resolved_host::update_with_ip(std::string possibly_IP) {

	// First check the traditional type of IP address (v4 and v6).
	if (inet_pton(AF_INET, possibly_IP.data(), &ipv4_addr) == 1) {
		ipv6 = false;
		return true;
	}

	if (inet_pton(AF_INET6, possibly_IP.data(), &ipv6_addr) == 1) {
		ipv6 = true;
		return true;
	}

	// Try to convert a raw number into an IPv4 address.
	char * end = NULL;
	long int x = strtol(possibly_IP.data(), &end, 0);
	size_t chars_in_number = end - possibly_IP.data();
	// If we didn't use the whole string when converting to a number,
	// that means the conversion was unsuccessful.
	if (chars_in_number != possibly_IP.size()) {
		return false;
	}

	// If the conversion was successful and within range, convert to
	// canonical form. NOTE: This does not recognize 0 as 0.0.0.0, but
	// that's not a valid address anyway so...
	if (x < UINT_MAX) {
		in_addr converted;
		converted.s_addr = htonl(x);

		char buf[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &converted, buf, sizeof(buf)) != NULL) {
			std::cout << possibly_IP << ": ipv4 address " << buf << std::endl;
			return true;
		}
	}

	return false;
}

// For keeping a record of a lookup failure.
class lookup_failure {
	public:
		int addrtype;
		std::string hostname;

		lookup_failure(int addrtype_in, std::string host) {
			addrtype = addrtype_in;
			hostname = host;
		}
};

typedef enum {DNS_OK, DNS_CNAME,
	DNS_TRYAGAIN, DNS_PERMANENT, DNS_EXCEPTIONAL} dns_errtype;

class adns_lookup {
	private:
		dns_errtype error_type(adns_status error) const;

		adns_query add_lookup(std::string host, adns_state & ads,
			adns_rrtype lookup_type);

		std::string nameservers_to_strcfg(
			const std::vector<std::string> & nameservers);

		// Get a list of wildcard domains that, if it exists,
		// would automatically resolve that host.
		std::set<std::string> get_wildcard_domains(
			const std::string & host);

		std::vector<std::string> get_wildcard_domains(
			const std::vector<std::string> & hosts);

		adns_state ads;
		adns_queryflags query_flags;

	public:
		std::map<std::string, std::vector<resolved_host> > host_to_IPs;

		// Organized by failure type. The former is for unknown hosts
		// (NXDOMAIN both by IPv4 and IPv6) while the latter is for
		// everything else.
		std::set<std::string> unknown_hosts;
		std::vector<lookup_failure> failures;

		adns_lookup(const std::vector<std::string> & name_servers);
		adns_lookup() : adns_lookup(std::vector<std::string>()) {};
		~adns_lookup();

		// No copy constructors because we need to call a finish
		// operator only once on the adns state when done.
		adns_lookup (const adns_lookup & other) = delete;

		void lookup(const std::vector<std::string> & hosts,
			int retries, bool check_wildcards);
};

dns_errtype adns_lookup::error_type(adns_status error) const {
	// We might get a timeout if the connection is acting up; or we might get
	// misqueries if the input's wrong or permfails if the domain simply
	// doesn't exist. Or we could be getting temporary errors.
	// Everything else is exceptional.

	if (error == adns_s_ok) { return DNS_OK; }

	// Domain doesn't exist or has no address of this type
	if (error == adns_s_nxdomain || error == adns_s_nodata) {
		return DNS_PERMANENT;
	}

	if (error == adns_s_prohibitedcname) { return DNS_CNAME; }

	if (error > adns_s_max_remotefail || error == adns_s_timeout) {
		return DNS_TRYAGAIN;
	}
	return DNS_EXCEPTIONAL;
}

adns_query adns_lookup::add_lookup(std::string host, adns_state & ads,
	adns_rrtype lookup_type) {

	adns_query quer = NULL;
	adns_submit(ads, host.data(), lookup_type, query_flags, NULL, &quer);
	return quer;
}

std::string adns_lookup::nameservers_to_strcfg(
	const std::vector<std::string> & nameservers) {

	// Max 5
	if (nameservers.size() > 5) {
		throw std::runtime_error("nameservers_to_strcfg: "
			"Can't specify more than 5 name servers!");
	}

	if (nameservers.empty()) { return ""; }

	std::string output = "nameserver " + nameservers[0];

	for (size_t i = 1; i < nameservers.size(); ++i) {
		output += " " + nameservers[i];
	}

	return output;
}

std::set<std::string> adns_lookup::get_wildcard_domains(
	const std::string & host) {

	std::set<std::string> wildcards_set;

	std::vector<std::string> host_suffixes = all_substrs(
		host, ".");
	if (host_suffixes.empty()) {
		return wildcards_set;
	}

	host_suffixes.pop_back(); // Don't want e.g. ".com"
	for (std::string superdomain: host_suffixes) {
		wildcards_set.insert("*" + superdomain);
	}

	return wildcards_set;
}

std::vector<std::string> adns_lookup::get_wildcard_domains(
	const std::vector<std::string> & hosts) {

	std::set<std::string> wildcards_set;

	// This is somewhat slow. Fix if it becomes troublesome.
	for (std::string host: hosts) {
		for (std::string wildcard: get_wildcard_domains(host)) {
			wildcards_set.insert(wildcard);
		}
	}

	std::vector<std::string> wildcards;
	std::copy(wildcards_set.begin(), wildcards_set.end(),
		std::back_inserter(wildcards));

	return wildcards;
}


adns_lookup::adns_lookup(const std::vector<std::string> & name_servers) {
	// Set up the ADNS state (with proper parameters)
	adns_initflags flags = (adns_initflags)(adns_if_nosigpipe | adns_if_noerrprint);

	// My ISP doesn't seem to like UDP, so always use TCP. We also want
	// the owner string to be passed through, and both IPv4 and IPV6
	// answers.
	query_flags = (adns_queryflags)(adns_qf_usevc | adns_qf_quoteok_query
		| adns_qf_owner | adns_qf_want_ipv4 | adns_qf_want_ipv6);
	if (name_servers.empty()) {
		adns_init(&ads, flags, NULL);
	} else {
		adns_init_strcfg(&ads, flags, NULL,
			nameservers_to_strcfg(name_servers).data());
	}
}

adns_lookup::~adns_lookup() {
	adns_finish(ads);
}

void adns_lookup::lookup(const std::vector<std::string> & hosts,
	int retries, bool check_wildcards) {

	// If we're asked to check wildcards, first do lookups on them.
	if (check_wildcards) {
		lookup(get_wildcard_domains(hosts), retries, false);
	}

	std::vector<adns_query> queries;

	for (std::string host: hosts) {
		resolved_host resolved;

		// If we've determined that the host is unknown, don't
		// try again. (This also stops duplicate queries, although
		// the way it does so may be a little ugly.)
		if (unknown_hosts.find(host) != unknown_hosts.end()) {
			continue;
		}

		// If we've already looked up this host, skip.
		if (host_to_IPs.find(host) != host_to_IPs.end()) {
			std::cout << "Exact match: " << host << std::endl;
			continue;
		}

		// If we have entries for applicable wildcard hosts, use them
		// instead of looking up again.
		bool found_wildcard = false;
		for (std::string wildcard: get_wildcard_domains(host)) {
			if (host_to_IPs.find(wildcard) != host_to_IPs.end()) {
				host_to_IPs[host] = host_to_IPs[wildcard];
				found_wildcard = true;
				std::cout << "Wildcard match: " << host << " <- " << wildcard << std::endl;
			}
		}

		if (found_wildcard) { continue; }

		// If this host is an IP address, just push it onto the map.
		if (resolved.update_with_ip(host)) {
			host_to_IPs[host].push_back(resolved);
			continue;
		}
		// IPv4
		queries.push_back(add_lookup(host, ads, adns_r_a));

		// IPv6
		queries.push_back(add_lookup(host, ads, adns_r_aaaa));

		// Add every host to the unknown host set; we'll remove them after
		// a successful lookup.
		unknown_hosts.insert(host);
	}

	// For following (strictly speaking out of spec) CNAME chains, e.g.
	// www.ouest-france.fr -> ouest-france.edgekey.net ->
	// e4311.a.akamaiedge.net -> IP.
	std::map<std::string, std::string> cname_chain;

	// Keep track of how many times we've tried to resolve a hostname.
	std::map<std::pair<std::string, int>, int> times_retried;

	// Go through the list of pending queries in a way that handles
	// new elements being added to the end.
	for (size_t i = 0; i < queries.size(); ++i) {
		adns_answer* answer;
		int res = adns_wait(ads, &queries[i], &answer, NULL);
		if (res) {
			throw std::logic_error("Error while waiting for DNS response: " +
				std::string(strerror(res)));
		}

		std::string host = answer->owner;

		char buf[INET6_ADDRSTRLEN];

		// If we didn't get any errors, incorporate the information into
		// our host lookup structures.
		switch(error_type(answer->status)) {
			case DNS_OK:
				for (size_t i = 0; i < answer->nrrs; ++i) {
					resolved_host host_record;
					if (answer->type == adns_r_a) { // IPv4
						host_record.ipv6 = false;
						host_record.ipv4_addr = answer->rrs.inaddr[i];
					} else if (answer->type == adns_r_aaaa) { // IPv6
						host_record.ipv6 = true;
						host_record.ipv6_addr = answer->rrs.in6addr[i];
					} else {
						std::cout << "dns lookup: Unknown address type!";
					}

					std::string name = answer->owner;
					host_to_IPs[name].push_back(host_record);

					// If we're at the end of a cname chain, follow it.
					while (cname_chain.find(name) != cname_chain.end()) {
						name = cname_chain.find(name)->second;
						host_to_IPs[name].push_back(host_record);
					}

					// Set the IP for any alias we may have.
					if (answer->cname != NULL) {
						host_to_IPs[answer->cname].push_back(host_record);
					}
				}
				break;
			// If we got a (technically out of spec) CNAME chain which points
			// a name only at another name, then follow the chain by sending a
			// new request. This is a bit wasteful: it'll try to follow the same
			// chain both by IPv4 and IPv6. Fix later if it turns out too slow.
			case DNS_CNAME:
				cname_chain[answer->cname] = answer->owner;
				// Descend down the cname chain by requesting the alias.
				queries.push_back(add_lookup(answer->cname, ads, answer->type));
				break;
			case DNS_TRYAGAIN: {
				// Some of these are actually recoverable (the server we're
				// querying is erring out), but other errors are really just
				// the DNS server reporting the error it got. So retry a number of
				// times, then give up.
				std::cout << "Recoverable error for " << host << ": " <<
					adns_strerror(answer->status) << std::endl;

				// Submit again unless we've tried too many times.
				std::pair<std::string, int> host_and_type(host, answer->type);
				if (times_retried[host_and_type] < retries) {
					queries.push_back(add_lookup(host, ads, answer->type));
					++times_retried[host_and_type];
				} else {
					// It's no longer an unknown host, just a failed one.
					unknown_hosts.erase(host);
					failures.push_back(lookup_failure(answer->type,host));
				}
				break;
			}
			case DNS_PERMANENT:
				failures.push_back(lookup_failure(answer->type,host));
				break;
			// These errors are exceptional and shouldn't happen as part of normal
			// functioning.
			case DNS_EXCEPTIONAL:
			default:
				throw std::logic_error("DNS lookup error for host " +
					host + ": " + adns_strerror(answer->status));
		};

		free(answer);
	}

	// Remove every host that we now know from the unknown hosts list.
	for (auto pos = host_to_IPs.begin(); pos != host_to_IPs.end(); ++pos) {
		unknown_hosts.erase(pos->first);
	}
}

/*
int main() {
	adns_lookup dns_lookup({"8.8.8.8", "8.8.4.4"});
	dns_lookup.lookup({"ns1.wordpress.com", "ns2.wordpress.com"}, 3, true);
	dns_lookup.lookup({"www.wordpress.com", "*.blogspot.com"}, 3, true);

	for (lookup_failure failed: dns_lookup.failures) {
		std::cout << "Failed: " << failed.addrtype << ", " << failed.hostname << std::endl;
	}

	for (auto pos = dns_lookup.host_to_IPs.begin(); pos != dns_lookup.host_to_IPs.end();
		++pos) {
		std::cout << "Entry for " << pos->first << std::endl;
	}
}*/