// TODO: Rate-limiting. Probably just "ms per request", then check whenever we
// would add another request, if the last request happened too recently.

#include "slurper.h"

#include <iostream>
#include <fstream>
#include <set>

#include <assert.h>

size_t easy_handle_container::store_data(char *ptr, size_t size, size_t nmemb,
		std::vector<char> * databuf_passthrough) {

	size_t bytes_to_add = nmemb * size;
	std::copy(ptr, ptr+bytes_to_add, std::back_inserter(*databuf_passthrough));

	return bytes_to_add;
}

// Initialize the class.
void curl_slurper::init(int ID) {
	slurper_ID = ID;
}

// Perhaps this should be in easy_handle_container instead? TODO?
response curl_slurper::create_response(const easy_handle_container & container,
	const CURLMsg & multi_metadata) {

	// should never vary from this
	assert(multi_metadata.msg == CURLMSG_DONE);

	response resp;
	resp.requested_URL = container.requested_URL;
	char * content_type;

	CURL * easy_handle = container.handle;
	CURLcode result;

	if (multi_metadata.data.result != CURLE_OK) {
		// Pass an error code for now.
		resp.error = container.err_buf;
		return resp;
	}

	curl_easy_getinfo(easy_handle, CURLINFO_RESPONSE_CODE, &resp.status_code);

	// Handle redirects.
	// TODO: More strict treatment of such. See Python code.
	if (resp.status_code >= 300 && resp.status_code < 400) {
		char * new_location;
		result = curl_easy_getinfo(easy_handle,
			CURLINFO_REDIRECT_URL, &new_location);

		// I don't know why the new location can be NULL if we get a redirect,
		// but perhaps some web servers don't care to send a new location?
		// Whatever.
		if (result == CURLE_OK && new_location != NULL) {
			resp.redirect_to_URL = new_location;
		}
	}

	// Get timestamp if we got any info.
	result = curl_easy_getinfo(easy_handle, CURLINFO_FILETIME, &resp.timestamp);
	resp.has_timestamp = (result == CURLE_OK) && (resp.timestamp > 0);

	// Get content type. TODO: Turn into a mimetype or somehow use two fields
	// for this so that it's clear that inferring the mimetype by libmagic
	// only does that, it doesn't provide encoding or similar.
	result = curl_easy_getinfo(easy_handle, CURLINFO_CONTENT_TYPE, &content_type);
	// See my remark about location. Sometimes content_type is NULL even though
	// the result shows that getting the info succeeded. I don't know why.
	if (result == CURLE_OK && content_type != NULL) {
		resp.mime_type = content_type;
	}

	resp.data = container.data_buffer;
	return resp;
}

// To halt the thread, pass an appropriate command.
void curl_slurper::continuous_download(
	std::shared_ptr<safe_queue<work_order> > work_queue_ptr,
	std::shared_ptr<safe_queue<response> > results_queue) {

	const int	poll_wait_time = 1000,	// ms
				max_connections = 32;	// to the same host (per thread)

	CURLM *multi_handle = curl_multi_init();
	curl_slist *dns_cache = NULL;

	// Share some stuff among all easy_handles for this thread.
	CURLSH *share = curl_share_init();
	curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
	curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);

	// We're usually restricted to one host, so make the limits equal.
	// Looks like this is global, i.e. across every multi_handle... somehow?
	// so it needs to be multiplied by the number of threads. IDK. That made my
	// connection hang...
	curl_multi_setopt(multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, max_connections);
	curl_multi_setopt(multi_handle, CURLMOPT_MAX_HOST_CONNECTIONS, max_connections);

	/* enables http/2 if available */
	#ifdef CURLPIPE_MULTIPLEX
		curl_multi_setopt(multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
	#endif

	bool working = true;
	set_done(false);

	int numfds, handles_running, msgs_left;
	int URLs_running = 0;

	while (working) {
		// Create new handles for every URL that's queued. libcurl will make sure
		// that we don't connect with more than a given number of connections
		// for this multi_connection, so we don't have to keep track of that
		// ourselves.

		// Since the timeout counters start counting when the handle is added,
		// not when the connection is actually made, we don't want to spam too
		// much. Hence we strictly limit the number of URLs running (i.e. sent
		// to libcurl) to max_connections.

		std::pair<bool, work_order> URL_or_none;
		URL_or_none.first = true;

		while (URLs_running < max_connections
			&& URL_or_none.first) {

			URL_or_none = work_queue_ptr->poll_dequeue();
			if (!URL_or_none.first) {
				continue;
			}

			work_order work = URL_or_none.second;

			// Did we get the poison pill?
			if (work.type == W_QUIT) {
				std::cout << slurper_ID <<
					": Received poison pill, exiting once done!" << std::endl;
				working = false;
				work_queue_ptr->notify_work_done();
				continue;
			}

			// Is the work order for some DNS info?
			if (work.type == W_HOST_IP) {
				// Add the required DNS information to the DNS cache.
				// In theory there might be a problem with stale pointers to
				// the dns cache as we append new information, but it seems
				// to work in practice -- probably because it's a linked
				// list.
				dns_cache = curl_slist_append(dns_cache,
					std::string(work.hostname + ":443:" + work.IP).data());
				dns_cache = curl_slist_append(dns_cache,
					std::string(work.hostname + ":80:" + work.IP).data());
				work_queue_ptr->notify_work_done();
				continue;
			}

			// cURL uses a GC-like setup where it's libcurl's responsibility to
			// juggle the easy handle pointers. Since these aren't smart, we have
			// no way to determine whether they're in use or not until the library
			// sends a message referring to one of them. RAII can cause lots of
			// trouble here, thus I just manually new and delete for now.

			// Perhaps there's a better way (possibly with a finite pool or
			// something), but I haven't found one yet. Fix later.
			easy_handle_container * new_url_req = new easy_handle_container;

			curl_easy_setopt(new_url_req->handle, CURLOPT_SHARE, share);
			curl_easy_setopt(new_url_req->handle, CURLOPT_RESOLVE, dns_cache);
			new_url_req->prepare_download(work.URL);

			curl_multi_add_handle(multi_handle, new_url_req->handle);
			++URLs_running;
		}

		// Wait for something to happen.
		curl_multi_poll(multi_handle, NULL, 0, poll_wait_time, &numfds);
		curl_multi_perform(multi_handle, &handles_running);

		// Handle any finished stuff.
		CURLMsg *msg = NULL;
		while((msg = curl_multi_info_read(multi_handle, &msgs_left))) {
			if(msg->msg == CURLMSG_DONE) {
				easy_handle_container * handle_done;
				curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &handle_done);

				// Dump the response to the appropriate queue, and signal that the
				// work is done.
				results_queue->enqueue(create_response(*handle_done, *msg));
				work_queue_ptr->notify_work_done();
				--URLs_running;

				// Detach the container from the multi_handle, then remove the latter.
				curl_multi_remove_handle(multi_handle, msg->easy_handle);
				delete handle_done;
			} else {
				std::cout << "Something strange: " << msg->msg << std::endl;
			}
		}
	}

	// We drop here after receiving the poison pill and every container has been
	// handled. Clean up the multi handle and indicate that we're exiting.

	curl_multi_cleanup(multi_handle);
	curl_share_cleanup(share);
	curl_slist_free_all(dns_cache);
	set_done(true);
}