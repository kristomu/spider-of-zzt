#pragma once

#include "../archive_parser.h"
#include <src/lib7zip.h>

// In-memory shims for interacting with lib7zip
#include "memory_in_stream.h"
#include "memory_out_stream.h"

// ------------------------------------------------------------------------ //

// KNOWN BUGS:
//		- Doesn't report CRC errors.
//			(This is a lib7zip bug, see src/7ZipArchive.cpp's SetOperationResult,
//			 and compare to p7zip's CPP/7zip/UI/Client7z/Client7z.cpp.)
//		- Depends on file extension, e.g. can't open a ZIP file if the extension
//			is LHA. (This may prove a problem. Again, the 7z executable does
//			the right thing, so it's not inherent to p7zip.)

// Missing features:
//		- There's no way to detect a lack of rar5 support. I'd like
//			zzt_interesting to err out with "put codecs/rar.so in your library
//			path", but I can't do that.

// ------------------------------------------------------------------------ //

// TODO? A way of marking particular paths as done (decompressed without
// errors) so if we use multiple parsers, they don't redo stuff that's
// already been done...

class lib7zip_parser : public archive_parser {
	private:
		// Deal with this later
		// Also should be const, but lib7zip doesn't have the required
		// function marked const so...
		std::vector<std::string> get_supported_extensions();

		C7ZipLibrary lib;
		C7ZipArchive * archive;
		C7ZipArchiveItem * archive_item;

		unsigned int num_entries = 0, next_entry;
		bool error;

		mem_stream in_stream;
		mem_out_stream out_stream;

		std::string error_msg = "";

	public:

		std::string entry_pathname;
		size_t entry_file_size;
		bool clean_exit;

		lib7zip_parser() {
			archive = NULL;
			archive_item = NULL;

			if (!lib.Initialize()) {
				throw std::logic_error("Can't initialize C7ZipLibrary!");
			}
		}

		~lib7zip_parser() {
			if (archive != NULL) {
				delete archive;
			}
		}


		void read_archive(const std::string & file_path,
			const std::vector<char> & contents_bytes);

		// This reads the next entry's metadata (file size, etc).
		read_state read_next_header();

		// Uncompress an entry (inner file) to the given vector, clearing it
		// beforehand.
		// Returns the number of bytes read. < 0 if something happened.
		int uncompress_entry(std::vector<char> & unpacked_bytes_dest);

		// Get an error, or empty string for none.
		std::string get_error() const;

		// TODO? Manual cleanup for not keeping a bunch of archive data in
		// memory any longer than needed???

		// TODO: Static method that gives the extensions and mimetypes
		// it can handle.
};