#pragma once

#include "archive_parser.h"

#include <archive_entry.h>	// Recursive search inside ZIP files
#include <archive.h>		// Ditto

class libarchive_parser : public archive_parser {
	private:
		archive * cur_archive;
		archive_entry * entry;
		std::string coarse_error;

		std::string get_coarse_libarchive_error(
			int libarchive_ret_val) const;

	public:

		std::string entry_pathname;
		size_t entry_file_size;

		libarchive_parser() { cur_archive = NULL; }

		~libarchive_parser() {
			if (cur_archive != NULL) {
				archive_read_free(cur_archive);
			}
		}

		// This function reads the archive contained in contents_bytes.
		void read_archive(const std::vector<char> & contents_bytes);

		// This reads the next entry's metadata (file size, etc).
		read_state read_next_metadata();

		// Uncompress an entry (inner file) to the given vector, clearing it
		// beforehand.
		// Returns the number of bytes read. < 0 if something happened.
		int uncompress_entry(std::vector<char> & unpacked_bytes_dest);

		// Get an error, or empty string for none.
		std::string get_error();

		// TODO? Manual cleanup for not keeping a bunch of archive data in
		// memory any longer than needed???

		// TODO: Static method that gives the extensions and mimetypes
		// it can handle.
};
