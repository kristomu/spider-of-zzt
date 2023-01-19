#pragma once

// An in-memory C7Zip output stream.

#include <src/lib7zip.h>
#include <cstdlib>
#include <string>
#include <vector>
#include <stdexcept>

class mem_out_stream : public C7ZipOutStream {
	private:
		std::vector<char> output_data;
		size_t cur_pos;

	public:
		void clear() {
			output_data.clear();
			cur_pos = 0;
		}

		mem_out_stream() { clear(); }

		std::vector<char> vec() { return output_data; }

		int GetFileSize() const {
			return output_data.size();
		}

		// "Write" to the output data array. If something was
		// written and processsed_size is not NULL, is should contain
		// the number of bytes actually written (which is always the
		// number asked for in this case; we assume the file can
		// fit in memory.).
		int Write(const void * data, unsigned int size,
			unsigned int * processed_size) {

			// Note to self: insert() invalidates iterators. Use
			// counts instead (like this).
			output_data.insert(output_data.begin() + cur_pos,
				(char *)data, (char *)data+size);

			if (size >= 0 && processed_size != NULL) {
				*processed_size = size;
				cur_pos += size;
			}

			return 0;
		}

		// Seek to the middle of the output file. This will really slow
		// down insertion; I'll deal with it if my lib7zip interface turns
		// out to actually do a significant amount of seeking.
		int Seek(__int64 offset, unsigned int whence,
			unsigned __int64 * new_position);

		int SetSize(unsigned __int64 size) {
			// This should never happen.
			throw std::logic_error("memory_out_stream: caller tried to set size");
		}
};
