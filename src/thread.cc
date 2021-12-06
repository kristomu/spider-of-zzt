#include <iostream>
#include <thread>
#include <vector>

#include "slurper.h"

#include <unistd.h>

int main() {
	curl_global_init(CURL_GLOBAL_DEFAULT); // Must be called only once. TODO, fix this

	std::shared_ptr<safe_queue<work_order> > URLs =
		std::make_shared<safe_queue<work_order> >();

	URLs->fill({
		work_order("https://example.com/"),
		work_order("https://www.vg.no/"),
		work_order("https://dontexist/"),
		work_order("aol://unsupported/"),
		work_order("https://edition.cnn.com/"),
		work_order("https://www.oocities.org/SunsetStrip/Alley/8447/kh2.html")
	});

	std::vector<curl_slurper> slurpers;
	std::vector<std::shared_ptr<safe_queue<work_order> > > slurper_queues;
	std::shared_ptr<safe_queue<response> > results_queue =
		std::make_shared<safe_queue<response> >();

	std::vector<std::thread> threads;

	int numthreads = 1;

	slurper_queues.push_back(URLs);
	slurpers.push_back(curl_slurper(1));

	//slurpers[0].continuous_download(URLs, results_queue, signal_queue);

	for (int i = 0; i < numthreads; ++i) {
		threads.push_back(std::thread(&curl_slurper::continuous_download,
			&slurpers[0], URLs, results_queue));
		threads[i].detach();
	}

	// Wait on this thread just for a proof of concept.
	do {
		sleep(1);
	} while (!slurper_queues[0]->work_done());

	// Shut down the threads
	for (auto pos = slurper_queues.begin(); pos != slurper_queues.end(); ++pos) {
		(*pos)->enqueue(work_order(W_QUIT));
	}

	std::vector<response> responses;
	results_queue->output(responses);
	for (const response & res: responses) {
		std::cout << "Response: URL: " << res.requested_URL << " error: "
			<< res.error << " data size: " << res.data.size() << std::endl;
	}

	sleep(1);

	curl_global_cleanup();

	return 0;
}