#include "libarchive.h"
#include <stdexcept>

// TODO: Clean up to properly return error values, etc.
// But first get this working!

void libarchive_parser::read_archive(const std::vector<char> & contents_bytes) {
	int ret_val;

	cur_archive = archive_read_new();
	archive_read_support_filter_all(cur_archive);
	archive_read_support_format_all(cur_archive);
	ret_val = archive_read_open_memory(cur_archive, contents_bytes.data(),
		contents_bytes.size());

	if (ret_val != ARCHIVE_OK) {
		std::string err = archive_error_string(cur_archive);
		//archive_read_free(cur_archive);
		throw std::runtime_error("Error unpacking archive: " + err);
	}
}

// Returns false if it can't read the next metadata, and sets clean_exit
// to false if that was unexpected. If true, it also populates entry info
// as a side effect.
bool libarchive_parser::read_next_metadata() {
	int x_ret_val = archive_read_next_header(cur_archive, &entry);
	if (x_ret_val != ARCHIVE_OK && x_ret_val != ARCHIVE_WARN) {
		// If the reason we stop parsing is unexpected, set a
		// boolean to that effect.
		if (x_ret_val != ARCHIVE_EOF) {
			clean_exit = false;
		}
		clean_exit = true;
		return false;
	}

	// Work around a libarchive limitation where non-ASCII letters can
	// cause archive_entry_pathname to return NULL.
	// I can't be arsed to fix it in source.
	// https://github.com/libarchive/libarchive/issues/1572
	entry_pathname = "<UNKNOWN FOREIGN>";
	const char * pathname_ptr = archive_entry_pathname(entry);
	if (pathname_ptr != NULL) {
		entry_pathname = pathname_ptr;
	}

	entry_file_size = archive_entry_size(entry);

	return true;
}

int libarchive_parser::uncompress_entry(std::vector<char> &unpacked_bytes_dest) {
	unpacked_bytes_dest.resize(entry_file_size);
	return archive_read_data(cur_archive,
		unpacked_bytes_dest.data(), unpacked_bytes_dest.size());
}

std::string libarchive_parser::get_error() {
	// TODO, make this proper. If the error string is "", check
	// if ret_val indicates an error, and if so, return it.
	return archive_error_string(cur_archive);
}
