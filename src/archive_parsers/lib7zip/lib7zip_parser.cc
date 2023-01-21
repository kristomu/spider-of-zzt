#include "lib7zip_parser.h"
#include <src/lib7zip.h>

#include <stdexcept>

std::vector<std::string> lib7zip_parser::get_supported_extensions() {
	WStringArray exts;

	if (!lib.GetSupportedExts(exts)) {
		throw std::runtime_error("Couldn't get supported extensions");
	}

	std::vector<std::string> extensions;

	for (const wstring ext: exts) {
		std::string extsimple(ext.begin(), ext.end());
	}

	return extensions;
}

// This function reads the archive contained in contents_bytes.
void lib7zip_parser::read_archive(
	const std::string & file_path,
	const std::vector<char> & contents_bytes) {

	// TODO: get the file format. Or circumvent the problem
	// by modifying lib7zip.
	in_stream.set(file_path, contents_bytes);
	error_msg = "";

	num_entries = 0;
	next_entry = 0;

	// Enable signature checking to also recognize archives with
	// the wrong extension. (NOTE: This may fail for .dmg files.)
	if (!lib.OpenArchive(&in_stream, &archive, true)) {
		// That's all the error you get... Although for this, there's
		// a particular workaround.
		switch(lib.GetLastError()) {
			case lib7zip::LIB7ZIP_NO_ERROR:
				error_msg = "Error getting error type.";
				break;
			default:
			case lib7zip::LIB7ZIP_UNKNOWN_ERROR:
				error_msg = "Unknown error.";
				break;
			case lib7zip::LIB7ZIP_NEED_PASSWORD:
				error_msg = "Archive is password protected.";
				break;
			case lib7zip::LIB7ZIP_NOT_SUPPORTED_ARCHIVE:
				error_msg = "Archive type is not supported.";
				break;
		}
		throw std::runtime_error("p7zip: Error unpacking archive: " + error_msg);
	}

	archive->GetItemCount(&num_entries);
}

// This reads the next entry's metadata (file size, etc). Return false if there
// are no more.
// TODO: use enum instead: OK, all done, recoverable error
// (just go to the next one, but ask for an error first)
// and unrecoverable error (stop).
read_state lib7zip_parser::read_next_header() {
	if (next_entry == num_entries) {
		return AP_DONE;
	}

	if (archive->GetItemInfo(next_entry++, &archive_item)) {
		// Load the relevant header. The lib7zip index names
		// we're interested in are:
		// lib7zip::kpidPath		- Pathname (load into entry_pathname)
		// lib7zip::kpidSize		- Uncompressed size (entry_file_size)

		// These might also be interesting for future uses (e.g.
		// filtering release dates):
		// "kpidMTime"		- modified time

		unsigned __int64 size;
		std::wstring pathname;

		if (!archive_item->GetUInt64Property(
			lib7zip::kpidSize, size)) {
			error_msg = "Error getting entry header: file size.";
			// We can't filter out zip bombs etc if we don't know the size
			// of the file; so skip.
			return AP_SKIP;
		}
		entry_file_size = size;

		if (!archive_item->GetStringProperty(
			lib7zip::kpidPath, pathname)) {
			entry_pathname = "<UNKNOWN>";
		} else {
			entry_pathname = std::string(pathname.begin(), pathname.end());
		}
		return AP_OK;
	} else {
		error_msg = "Error getting entry header.";
		return AP_SKIP;
	}
}

// Uncompress an entry (inner file) to the given vector, clearing it
// beforehand.
/// Returns the number of bytes read. < 0 if something happened.
int lib7zip_parser::uncompress_entry(std::vector<char> & unpacked_bytes_dest) {
	out_stream.clear();
	bool ok = archive->Extract(archive_item, &out_stream);

	if (ok) {
		unpacked_bytes_dest = out_stream.vec();
		// ??? Should be size_t no?
		int bytes_unpacked = unpacked_bytes_dest.size();
		out_stream.clear();
		return bytes_unpacked;
	} else {
		// Something went wrong; get the extract error from lib7zip.
		std::wstring error_msg_wst = archive->GetLastExtractError();
		error_msg = std::string(error_msg_wst.begin(), error_msg_wst.end());
		return -1;
	}
}

/// Get an error, or empty string for none.
std::string lib7zip_parser::get_error() const {
	return error_msg;
}