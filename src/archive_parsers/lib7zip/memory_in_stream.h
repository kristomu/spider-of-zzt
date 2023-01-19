#pragma once

// An in-memory C7Zip input stream. Note that it stores the data itself;
// if that becomes a memory problem, replace it with an auto_ptr or
// something...

#include <src/lib7zip.h>
#include <cstdlib>
#include <string>
#include <vector>
#include <stdexcept>

class mem_stream : public C7ZipInStream {
	private:
		std::vector<char> contents_bytes;
		std::string filename;
		wstring m_strFileExt;
		size_t current_position;

	public:
		void set(std::string filename_in,
			std::vector<char> contents_in);

		mem_stream() {}

		mem_stream(std::string filename_in,
			const std::vector<char> & contents_in) {
			set(filename_in, contents_in);
		}

		std::string get_filename() const { return filename; }

		wstring GetExt() const {
			return m_strFileExt;
		}

		int Read(void * data, unsigned int bytes_to_read,
			unsigned int * processed_size);
		int Seek(__int64 offset, unsigned int whence,
			unsigned __int64 * new_position);
		int GetSize(unsigned __int64 * size);
};
