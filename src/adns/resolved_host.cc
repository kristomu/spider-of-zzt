#include "resolved_host.h"
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
	// canonical form.
	if (x < UINT_MAX) {
		in_addr converted;
		converted.s_addr = htonl(x);

		char buf[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &converted, buf, sizeof(buf)) != NULL) {
			ipv6 = false;
			ipv4_addr = converted;
			return true;
		}
	}

	return false;
}