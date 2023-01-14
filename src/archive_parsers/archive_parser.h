#pragma once

// This is an abstract class for archive parsers.
// These are used by zzt_interesting to open archives and read
// the contents in them.

#include <vector>
#include <string>

class archive_parser {
	public:
		virtual ~archive_parser() {};

		// This function reads the archive contained in contents_bytes.
		virtual void read_archive(const std::vector<char> & contents_bytes) = 0;

		// This reads the next entry's metadata (file size, etc).
		virtual bool read_next_metadata() = 0;

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
