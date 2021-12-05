// https://stackoverflow.com/questions/15278343
// Somewhat augmented.
// Replace later if required.

#pragma once

#include <queue>
#include <mutex>
#include <climits>
#include <condition_variable>

// A threadsafe-queue.
template <class T> class safe_queue {
private:
	std::queue<T> queue;
	mutable std::mutex m;
	std::condition_variable c;
	unsigned int outstanding_work;

public:
	safe_queue(void) : queue(), m(), c() {
		outstanding_work = 0;
	}

	void fill(std::vector<T> contents) {
		for (T val: contents) {
			enqueue(val);
		}
	}

	void output(std::vector<T> & output) {
		while (!queue.empty()) {
			output.push_back(dequeue());
		}
	}

	~safe_queue() {}

	// Add an element to the queue.
	void enqueue(T t) {
		std::lock_guard<std::mutex> lock(m);
		if (outstanding_work == UINT_MAX) {
			throw std::logic_error("enqueue: can't enqueue with "
				"outstanding work at UINT MAX");
		}
		queue.push(t);
		++outstanding_work;
		c.notify_one();
	}

	// Get the "front"-element.
	// If the queue is empty, wait till an element is available.
	T dequeue()	{
		std::unique_lock<std::mutex> lock(m);
		while(queue.empty())
		{
			// release lock as long as the wait and reaquire it afterwards.
			c.wait(lock);
		}
		T val = queue.front();
		queue.pop();
		return val;
	}

	// Get the queue size: used by the coordinator to check for feedback
	// from the slurpers.
	size_t size() const {
		std::lock_guard<std::mutex> lock(m);
		return queue.size();
	}

	bool empty() const {
		return size() == 0;
	}

	bool work_done() const {
		std::lock_guard<std::mutex> lock(m);
		//std::cout << "DEBUG: outstanding work = " << outstanding_work << std::endl;
		return outstanding_work == 0;
	}

	void notify_work_done() {
		std::lock_guard<std::mutex> lock(m);
		if (outstanding_work == 0) {
			throw std::logic_error("safe_queue: notify_work_done"
				" called with no outstanding work!");
		}
		--outstanding_work;
	}

	// Returns either false and default value, or true and the dequeued value
	// (if there was one in the queue).
	std::pair<bool, T> poll_dequeue() {
		std::lock_guard<std::mutex> lock(m);
		std::pair<bool, T> out;
		out.first = false;

		if (queue.empty()) {
			return out;
		}

		out.first = true;
		out.second = queue.front();
		queue.pop();
		return out;
	}

	std::pair<bool, T> wait_dequeue() {
		return std::pair<bool, T>(true, dequeue());
	}
};
