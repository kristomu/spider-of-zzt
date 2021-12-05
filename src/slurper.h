#include <curl/curl.h>
#include <memory>
#include <vector>

#include <unistd.h>

// There is no inversion of control here!
#include "safe_queue.h"

#include <iostream>

// BEWARE: This class does not do any mutexing of SSL libraries. So don't use
// OpenSSL. In addition, GnuTLS uses excessive memory storing certificate data
// (once per connection). So use libnss, not OpenSSL or GnuTLS.

// It also seems that NSS has a few leaks of its own, but as they're in the <100K
// range, I'm not going to bother chasing them down/fixing them.

// https://curl.se/libcurl/c/threadsafe.html
// https://github.com/curl/curl/issues/5102
// https://forums.cryptlex.com/t/valgrind-reports-memory-leak-on-linux/773

// TODO? use async (multi_*) instead? This would open multiple connections to the
// same host, but would also help deal with slow hosts like angelfire.

// Also TODO (later): Leaky bucket to throttle request rate, and proper data
// structures instead of std::string and std::vector<char> (must at least include
// metadata).

// From Python:
// Output: (error, timestamp, url, new_url, mime_type, response.status, content)

class response {
	public:
		std::string error;	// proper type later

		// Although file systems may provide a more granular time, neither
		// the HTTP standard nor the Internet Archive uses finer-grained
		// units than a second.
		bool has_timestamp;
		time_t timestamp;

		// Perhaps also ID of requested URL to avoid a wasteful db lookup
		std::string requested_URL;
		std::string redirect_to_URL;
		std::string mime_type;

		int status_code;	// HTTP return code, e.g. 200 = OK

		std::vector<char> data;
};

// metadata telling the coordinator about our ops

enum slurper_signal { S_WORK_DONE, S_QUIT };

class easy_handle_container {
	private:
		static size_t store_data(char * ptr, size_t size, size_t nmemb,
			std::vector<char> * databuf_passthrough);

	public:
		std::vector<char> data_buffer;
		char err_buf[CURL_ERROR_SIZE+1];
		CURL * handle;
		std::string requested_URL;

		void init() {
			handle = curl_easy_init();

			//curl_easy_setopt(handle, CURLOPT_VERBOSE, 1);

			curl_easy_setopt(handle, CURLOPT_USERAGENT,
				"Mozilla/5.0 (compatible; bot-SpiderOfZZT/0.1)");
			curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, err_buf);
			// ?? What would happen if this fails?
			curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, store_data);
			curl_easy_setopt(handle, CURLOPT_WRITEDATA, &data_buffer);

			// Set stuff we'd rather want to have
			// User agent, etc. TODO
			curl_easy_setopt(handle, CURLOPT_FILETIME, 1);
			// 5 minutes timeout
			curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 300L);
			curl_easy_setopt(handle, CURLOPT_TIMEOUT, 300L);

			// We need to be able to access the data from multi, so set a private
			// pointer.
			curl_easy_setopt(handle, CURLOPT_PRIVATE, this);
		}

		// Sets URL and clears the buffer
		void prepare_download(std::string URL) {
			init();
			requested_URL = URL;
			curl_easy_setopt(handle, CURLOPT_URL, URL.c_str());

			// Also set the referer to this URL to pass referer gates.
			curl_easy_setopt(handle, CURLOPT_REFERER, URL.c_str());
			data_buffer.clear();
		}

		easy_handle_container() {
			handle = NULL;
		}

		easy_handle_container(std::string URL) : easy_handle_container() {
			prepare_download(URL);
		}

		// We cannot have the same easy_handle in a copy, because that would
		// lead to crashes and/or cleanup trouble. So only copy the data buffer.
		easy_handle_container(const easy_handle_container & in) {
			//init();
			data_buffer = in.data_buffer;
		}

		void operator=(const easy_handle_container & in) {
			data_buffer = in.data_buffer;
		}

		~easy_handle_container() {
			if (handle) {
				curl_easy_cleanup(handle);
			}
		}
};

enum work_type {W_UNINITED, W_QUIT, W_URL, W_HOST_IP};

class work_order {
	public:
		work_type type;
		std::string URL; // if it's an URL
		// The remaining parameters are relevant to host_IP
		std::string IP;
		std::string hostname;

		work_order(std::string IP_in, std::string hostname_in) {
			type = W_HOST_IP;
			IP = IP_in;
			hostname = hostname_in;
		}

		work_order(std::string URL_in) {
			type = W_URL;
			URL = URL_in;
		}

		work_order() {
			type = W_UNINITED;
		}

		work_order(work_type type_in) { // For the poison pill W_QUIT
			type = type_in;
		}
};

class curl_slurper {

	private:
		bool idle, done;
		int slurper_ID;

		mutable std::mutex idle_mutex;

		void init(int ID);

		void set_idle(bool idle_status) {
			std::lock_guard<std::mutex> lock(idle_mutex);
			idle = idle_status;
		}

		void set_done(bool done_status) {
			std::lock_guard<std::mutex> lock(idle_mutex);
			done = done_status;
		}

		// Create a response from an easy_handle_container
		// containing a page downloaded with cURL.
		response create_response(const easy_handle_container & container,
			const CURLMsg & multi_metadata);

	public:

		curl_slurper(int ID) {
			init(ID);
		}

		// Only copy the ID when copying a slurper object.
		curl_slurper(const curl_slurper & in) {
			init(in.slurper_ID);
		}

		void operator=(const curl_slurper & in) {
			slurper_ID = in.slurper_ID;
		}

		bool is_idle() const {
			std::lock_guard<std::mutex> lock(idle_mutex);
			return idle;
		}

		bool is_done() const {
			std::lock_guard<std::mutex> lock(idle_mutex);
			return done;
		}

		int get_ID() const { return slurper_ID; }

		// Connect to a safe_queue and pop stuff off this queue

		void continuous_download(
			std::shared_ptr<safe_queue<work_order> > work_queue_ptr,
			std::shared_ptr<safe_queue<response> > response_queue);
};
