#include <string>

#include <netdb.h>
#include <arpa/inet.h>

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