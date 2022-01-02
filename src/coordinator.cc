
// The coordinator gives slurpers stuff to do (and later will deal with the responses).

// The general plan is that the coordinator gets URLs from somewhere (currently just a
// text file) and gives each URL with a host that resolves to the same IP to the slurper
// assigned to that IP. When it encounters a host with a new IP, it checks if there are
// any free slurpers available, and if so assigns that IP to the slurper.

// If a slurper runs out of things to do, the coordinator refills its queue with new
// entries with that IP. If there are none and the coordinator has checked the entire
// list, the slurper is then set as free.

// The structure thus consists of a mapping from hostnames to IP addresses,
// a map from IPs to queues of URLs that have not yet been added to slurpers, and
// a number of slurpers with associated IPs (or empty if they're free).

// TODO: Find a way of passing our DNS results through so curl doesn't do its own
// DNS lookup.

// TODO: Measure urls per sec and lookups per sec.
// TODO: Print start time (before lookup phases).

#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <map>
#include <set>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <unistd.h>
#include <nspr/prinit.h>

#include <thread>
#include "slurper.h"

#include "adns/adns.cc"
#include "zzt_interesting.cc"

// Ugly as sin. TODO: Replace with a proper library that can handle mailto etc.
std::string hostname(const std::string url) {
	size_t start = url.find("://");

	// Look for either : or /, so that we strip either the port or the /, whichever is
	// closer.
	size_t end = url.find_first_of("/:", start+3);
	if (start == std::string::npos || end == std::string::npos) {
		throw std::runtime_error("String is not a :// url: " + url);
	}
	// return substring between these.
	return std::string(url.begin()+start+3, url.begin()+end);
}

std::string now_str() {
	time_t now = time(NULL);
	return ctime(&now);
}

std::vector<work_order> get_URL_work_orders(const
	std::vector<std::string> & URLs) {

	std::vector<work_order> out;

	for (std::string URL: URLs) {
		out.push_back(work_order(URL));
	}

	return out;
}

int main() {
	std::map<std::string, std::vector<resolved_host> > host_to_IPs;
	std::map<resolved_host, std::vector<std::string> > URL_per_host;
	std::vector<std::string> input_URLs;

	std::ifstream URL_list_file("random_urls.txt");
	std::string line;

	while (std::getline(URL_list_file, line)) {
		input_URLs.push_back(line);
	}

	std::cout << "Phase zero completed at " << now_str() << std::endl;

	adns_lookup dns_lookup({/* CloudFlare */ "1.1.1.1", /* Google */ "8.8.8.8"});

	// First pass: find hostnames that we want to look up.
	// TODO: Handle duplicates in a way that's not a horrible horrible hack.

	std::vector<std::string> hostnames;
	std::set<std::string> seen; // HACK HACK
	for (std::string url: input_URLs) {
		std::string host = hostname(url);
		if (seen.find(host) != seen.end()) { continue; }

		hostnames.push_back(host);
		seen.insert(host);
	}

	dns_lookup.lookup(hostnames, 5);
	host_to_IPs = dns_lookup.host_to_IPs;

	// Second pass: Assign each URL to the appropriate host IP.
	// TODO: somehow populate

	for (std::string url: input_URLs) {
		std::string host = hostname(url);
		std::vector<resolved_host> host_info;

		if (host_to_IPs.find(host) != host_to_IPs.end()) {
			host_info = host_to_IPs[host];
		} else {
			std::cout << "Could not look up " << hostname(url) << "!\n";
			continue;
		}

		for (resolved_host h: host_info) {
			std::cout << "Lookup: " << hostname(url) << "\t" << h.rendered_ip() << std::endl;
		}

		// Perhaps spread the load out somehow? Or should this be the responsibility
		// of the slurper threads? In the latter case, we should use
		// vector<resolved_host> as the key. I'll figure something out.
		URL_per_host[host_info[0]].push_back(url);
	}

	// Then something like this...

	std::cout << "Phase one completed at " << now_str() << std::endl;
	time_t before_dl = time(NULL);

	curl_global_init(CURL_GLOBAL_ALL); // not thread safe

	// Turning this very high (e.g. 8) makes a lot of URLs fail. Why?
	// Also with optimization that happens. Why?
	int NUM_DISTINCT_IPS = 32;

	std::vector<curl_slurper> slurpers;
	std::vector<std::shared_ptr<safe_queue<work_order> > > slurper_queues;

	std::shared_ptr<safe_queue<response> > response_queue =
		std::make_shared<safe_queue<response> >();

	for (int i = 0; i < NUM_DISTINCT_IPS; ++i) {
		slurper_queues.push_back(std::make_shared<safe_queue<work_order> >());
		slurpers.push_back(curl_slurper(i));
	}

	int cur_thread = 0;

	std::vector<std::thread> threads;
	std::vector<bool> thread_assigned(NUM_DISTINCT_IPS, false);
	std::vector<resolved_host> thread_host(NUM_DISTINCT_IPS);

	for (cur_thread = 0; cur_thread < NUM_DISTINCT_IPS; ++cur_thread) {
		// Initialize a (currently idle) slurp thread.
		threads.push_back(std::thread(&curl_slurper::continuous_download,
			&slurpers[cur_thread], slurper_queues[cur_thread],
			response_queue));
		threads.rbegin()->detach();
	}

	int num_idle_threads = 0;

	// Set up a priority queue for providing work to the individual threads.
	// The point is to dispense the slowest tasks first, which is a reasonable
	// (1/3) approximation to the NP-hard multiprocessing scheduling optimum.
	std::priority_queue<std::pair<double, resolved_host> >
		host_by_expected_duration;

	for (auto pos = URL_per_host.begin(); pos != URL_per_host.end(); ++pos) {
		// Assume the time the work takes is proportional to the number of URLs.
		// It's not really a good assumption, particularly not when I later
		// will be limiting some URLs... but fix that later.
		host_by_expected_duration.push(
			std::pair<double, resolved_host>((double)pos->second.size(),
				pos->first));
	}

	bool all_idle = false;

	while (!all_idle) {
		std::cout << "It will be Short and it will be short. The time is " << now_str() << std::endl;
		// For any thread that's out of work, first check if we have
		// any work to give it (host_by_expected_duration isn't empty).
		// If we do, then assign it. If we don't, then skip.

		std::cout << "Host blocks remaining: " << URL_per_host.size()
			<< ", " << host_by_expected_duration.size() << std::endl;
		auto pos = URL_per_host.begin();

		all_idle = true;

		// TODO: Opportunistic refilling if required?
		for (cur_thread = 0; cur_thread < NUM_DISTINCT_IPS; ++cur_thread) {
			std::cout << "Status: thread " << cur_thread << ": "
				<< slurper_queues[cur_thread]->size()
				<< ", " << thread_host[cur_thread].rendered_ip() << " ";
			if (!slurper_queues[cur_thread]->work_done()) {
				std::cout << "Working" << std::endl;
				all_idle = false;
				continue;
			} else {
				std::cout << "Done" << std::endl;
			}

			if (host_by_expected_duration.empty()) {
				continue;
			}

			all_idle = false;

			std::pair<double, resolved_host> toughest_task =
				host_by_expected_duration.top();
			host_by_expected_duration.pop();

			std::cout << "Assigning " << toughest_task.second.rendered_ip() <<
				" with difficulty " << toughest_task.first <<
				" to thread " << cur_thread << std::endl;

			if (URL_per_host.find(toughest_task.second) == URL_per_host.end()) {
				throw std::logic_error("Tried to find host that doesn't exist! WTH?");
			}

			thread_host[cur_thread] = toughest_task.second;

			pos = URL_per_host.find(thread_host[cur_thread]);
			if (pos == URL_per_host.end() || pos->second.empty()) {
				std::cout << "Unexpected failure." << std::endl;
				continue;
			}

			std::cout << "Dumping " << pos->first.rendered_ip() << " to thread "
				<< cur_thread << std::endl;

			// Dump the DNS info first. This is kinda kludgy; I really should
			// ferry over the actual "hosts using this IP" information all
			// the way through. Also, what about hosts with multiple IPs?
			std::set<std::string> seen_hosts;
			for (std::string URL: pos->second) {
				if (seen_hosts.find(hostname(URL)) != seen_hosts.end()) { continue; }
				slurper_queues[cur_thread]->enqueue(work_order(
						pos->first.rendered_ip(), hostname(URL)));
				std::cout << "Enqueueing " << pos->first.rendered_ip() << ", " <<
					hostname(URL) << std::endl;
				seen_hosts.insert(URL);
			}

			// Give the URLs we have for this host to the thread in question
			slurper_queues[cur_thread]->fill(get_URL_work_orders(pos->second));

			// We've dumped everything. Clear the awaiting queue.
			URL_per_host.erase(thread_host[cur_thread]);
		}

		usleep(72703); //727003
	}

	// Shut down the threads
	for (auto pos = slurper_queues.begin(); pos != slurper_queues.end(); ++pos) {
		(*pos)->enqueue(work_order(W_QUIT));
	}

	// And wait for them all to be done.
	for (const curl_slurper & slurper: slurpers) {
		while (!slurper.is_done()) {
			sleep(1);
		}
		std::cout << "Done waiting on slurper " << slurper.get_ID() << std::endl;
	}

	std::cout << "Phase two completed at " << now_str() << std::endl;
	time_t after_dl = time(NULL);

	curl_global_cleanup();

	// Deal with some still reachable stuff to please valgrind.
	PR_Cleanup();

	std::vector<response> responses;
	response_queue->output(responses);
	std::cout << "Number of responses: " << responses.size() << std::endl;
	std::cout << "Phase two performance: " <<
		responses.size()/(double)(after_dl-before_dl) << " reqs/s." << std::endl;

	for (const response & res: responses) {
		std::cout << "Response: URL: " << res.requested_URL << " error: "
			<< res.error << " data size: " << res.data.size() << " interest:" << highest_priority_interest_type(res.requested_URL, "", res.data) << std::endl;
	}

	std::cout << "Phase three completed at " << now_str() << std::endl;
}
