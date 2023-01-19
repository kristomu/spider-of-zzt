#pragma once

// This is an abstract class for archive parsers.
// These are used by zzt_interesting to open archives and read
// the contents in them.

#include <vector>
#include <string>

// The read_next_metadata method returns a read_state. These read
// states are:
//		- AP_OK:	Everything's OK, proceed as normal
//		- AP_SKIP:  The metadata could not be read. It might be
//					partially read (in which case the parser should try
//					to extract), or not read at all, in which case the
//					parser should skip to the next entry. In either case,
//					get_error will contain more information about why the
//					metadata could not be read.
//		- AP_ERROR:	The archive is corrupted or encrypted and nothing more
//					can be read at all. Skip.
//		- AP_DONE:	Everything's OK but all the entries have been exhausted,
//					so there's nothing more to be read from the archive.

// TODO: Implement.

enum read_state { AP_OK, AP_SKIP, AP_ERROR, AP_DONE };

class archive_parser {
	public:
		virtual ~archive_parser() {};

		// This function reads the archive contained in contents_bytes.
		virtual void read_archive(const std::vector<char> & contents_bytes) = 0;

		// This reads the next entry's metadata (file size, etc).
		virtual read_state read_next_metadata() = 0;

		// Uncompress an entry (inner file) to the given vector, clearing it
		// beforehand.
		// Returns the number of bytes read. < 0 if something happened.
		virtual int uncompress_entry(std::vector<char> & unpacked_bytes_dest) = 0;

		// Get an error, or empty string for none.
		virtual std::string get_error() = 0;

		// TODO? Manual cleanup for not keeping a bunch of archive data in
		// memory any longer than needed???

		// TODO: Static method that gives the extensions and mimetypes
		// it can handle.
};
