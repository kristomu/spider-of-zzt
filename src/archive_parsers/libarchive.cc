#include "libarchive.h"
#include <stdexcept>

std::string libarchive_parser::get_coarse_libarchive_error(
	int libarchive_ret_val) const {

	switch(libarchive_ret_val) {
		case ARCHIVE_RETRY: return "ARCHIVE_RETRY";
		case ARCHIVE_WARN: return "ARCHIVE_WARN";
		case ARCHIVE_FAILED: return "ARCHIVE_FAILED";
		case ARCHIVE_FATAL: return "ARCHIVE_FATAL";
		default: return "Unknown libarchive error";
	}
}

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
// TODO: use enum instead: OK, all done, recoverable error
// (just go to the next one, but ask for an error first)
// and unrecoverable error (stop).
read_state libarchive_parser::read_next_header() {
	int hdr_read_status = archive_read_next_header(cur_archive, &entry);
	if (hdr_read_status != ARCHIVE_OK && hdr_read_status != ARCHIVE_WARN) {
		// If the reason we stop parsing is unexpected, set a
		// boolean to that effect.
		if (hdr_read_status != ARCHIVE_EOF) {
			coarse_error = get_coarse_libarchive_error(hdr_read_status);
			return AP_ERROR;
		}
		return AP_DONE;
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

	return AP_OK;
}

int libarchive_parser::uncompress_entry(std::vector<char> &unpacked_bytes_dest) {
	unpacked_bytes_dest.resize(entry_file_size);
	return archive_read_data(cur_archive,
		unpacked_bytes_dest.data(), unpacked_bytes_dest.size());
}

std::string libarchive_parser::get_error() const {
	std::string error = archive_error_string(cur_archive);
	if (error == "") {
		error = coarse_error;
	}

	return error;
}
