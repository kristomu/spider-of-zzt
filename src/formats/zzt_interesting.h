#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Functions for determining if data is interesting in a ZZT context.
// See zzt_interesting.cc for more information.

// This function returns the empty string if the file is neither a ZZT nor
// Super ZZT file, "zzt" if it's a ZZT file, and "szt" if it's a Super ZZT file.
std::string zzt_szt_check(const std::vector<char> & contents_bytes,
	bool multiple_boards_reqd);

// This function returns true if the vector (most likely) contains a ZZT
// or SZT board. Set check_zzt to true to check for a ZZT board, check_szt
// to true to check for Super ZZT, or both to check for both.
bool is_brd(const std::vector<char> & contents_bytes,
	bool check_zzt, bool check_szt);

// This checks for both.
bool is_brd(const std::vector<char> & contents_bytes);

// Returns "application/x-mzx-world", "application/x-mzx-board" or
// "application/x-mzx-save" if the file is any of these, otherwise
// returns the empty string.
std::string get_mzx_type(const std::vector<char> & contents_bytes);

// Auxiliary function for determining if something is valid UTF-8.
// Source: http://www.zedwood.com/article/cpp-is-valid-utf8-string-function

bool utf8_check_is_valid(const std::string & string);

// This is the output format for interesting components of a file.

// TODO: Somehow not print the hash if the file wasn't actually
// uncompressed, instead of outputting a hash for a zero byte file.

class interest_data {
	public:
		bool archive;
		int priority;				// higher is more important
		std::string internal_path;	// treats archives as directories
		std::string interest_type;
		std::string mime_type;		// for distinguishing false positives

		// Human-readable SHA224 hash of the file, used for filtering out
		// known ZZT files.
		std::string file_hash;

		// For reporting non-fatal errors that might still produce false
		// negatives (e.g. unsupported compression method, corrupted file).
		std::string error;

		bool is_error() const { return error != ""; }

		std::string str() const {
			std::string conclusion = interest_type;
			if (is_error()) {
				conclusion = " [ERR] " + error;
			}

			// Quick and dirty HACK to deal with non-UTF8 archive
			// names. It'd be better to just return them as bytes
			// to python and then try to decode there: or to be
			// more principled and do the charset decoding on a
			// filename basis here, and return a UTF-8 string.
			// but for now...
			std::string sanitized_path = internal_path;
			if (!utf8_check_is_valid(sanitized_path)) {
				for (char & x: sanitized_path) {
					if (x < 0) x = '_';
				}
			}

			// Ditto the conclusion, as some RAR-related libarchive error
			// messages also contain the filename.
			if (!utf8_check_is_valid(conclusion)) {
				for (char & x: conclusion) {
					if (x < 0) x = '_';
				}
			}

			if (conclusion == "") {
				return conclusion;
			}

			std::string preamble = "(mt: " + mime_type + ", sha224: " +
				file_hash + ") ";

			if (internal_path == "") {
				return preamble + conclusion;
			}

			if (archive) {
				return preamble + "archive[" + sanitized_path + "]:" + conclusion;
			} else {
				return preamble + sanitized_path + ":" + conclusion;
			}
		}

		bool interesting() const { return interest_type != ""; }

		interest_data() {}

		interest_data(int priority_in, const std::string & interest_type_in,
			const std::string & mime_type_in, const std::string & hash_in) {
			archive = false;
			priority = priority_in;
			interest_type = interest_type_in;
			mime_type = mime_type_in;
			file_hash = hash_in;
		}

		// Required by the Python vector indexing suite for some reason.
		bool operator==(const interest_data & other) const {
			return archive == other.archive &&
				priority == other.priority &&
				internal_path == other.internal_path &&
				interest_type == other.interest_type;
		}
};

// A report is a collection of data objects that give information
// about every interesting or erring part of a file.

class interest_report {
	public:
		std::vector<interest_data> results;
		std::vector<interest_data> errors;

		void add_entry(const interest_data & new_entry) {
			if (new_entry.is_error()) {
				errors.push_back(new_entry);
			} else {
				results.push_back(new_entry);
			}
		}

		interest_report() {}
		interest_report(interest_data sole_result) {
			add_entry(sole_result);
		}

		void operator+=(const interest_report & other) {
			std::copy(other.results.begin(), other.results.end(),
				std::back_inserter(results));
			std::copy(other.errors.begin(), other.errors.end(),
				std::back_inserter(errors));
		}

		void operator+=(const interest_data & new_entry) {
			add_entry(new_entry);
		}
};

// Outside-facing functions.

// Produce a report of all the interesting parts of a file with the given
// path and content. Recursion level is how many nested archives to decompress.

const int DEFAULT_RECURSION_LEVEL = 3;

// file_ok is set to false if this is called by a failing archive extraction
// (to get extension or similar), so that we know not to set a hash.
interest_report data_interest_type(const std::string & file_path,
	std::string mime_type, const std::vector<char> & contents_bytes,
	int recursion_level, bool file_ok);

interest_report data_interest_type(const std::string & file_path,
	std::string mime_type, const std::vector<char> & contents_bytes);

// WARNING: This reports errors as uninteresting even though they may be
// evidence of a false positive (corrupt archive that would contain
// something interesting if uncorrupted, e.g.)
bool is_data_interesting(std::string filename, std::string mime_type,
	const std::vector<char> & contents_bytes);

// Returns the highest priority report as a string.
std::string highest_priority_interest_type(const std::string & file_path,
	const std::string & mime_type, const std::vector<char> & contents_bytes);

// Unit tests.
bool TEST_interesting();