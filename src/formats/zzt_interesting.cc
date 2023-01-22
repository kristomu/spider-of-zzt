// Functions for determining if data is interesting in a ZZT context.
// This is ported from Python with some minor changes.
// TODO: Make keyword() for text and HTML behave like in Python.
// Also TODO: Fix the two time sinks, and implement zip unpacking behavior.
// And also also TODO? Return priority numbers as well as the string so that
// lesser interest (e.g. keyword) is overridden by greater (.ZZT file)?

// TODO: Fix illegal reads detected by valgrind.

// TODO: Handle .tar.gz files that are not explicitly marked as such.

#include <algorithm>
#include <iostream>
#include <iterator>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <memory>
#include <string>
#include <vector>

#include <magic.h>	// For mime-type inference

#include <archive_entry.h>	// Recursive search inside ZIP files
#include <archive.h>		// Ditto

#include <libxml/HTMLparser.h>	// HTML parsing (TODO: XML)
#include <openssl/sha.h>		// Hash calculations.

#include "../filetools.h"
#include "zzt_interesting.h"

#include "../archive_parsers/libarchive.h"
#include "../archive_parsers/lib7zip/lib7zip_parser.h"

// ZZT-specific headers and constants

struct zzt_header {
	int16_t magic;
	uint16_t boards;
};

struct brd_header {
	int16_t board_size;
	int8_t title_length;
};

const int ZZT_HEADER_MAGIC = -1, SUPERZZT_HEADER_MAGIC = -2;

// Determine various types of magic information: mime encoding and type.
// Only looks at the first 1K for speed if quick is enabled.
std::string get_magic(const std::vector<char> & contents_bytes, int type,
	bool quick) {

	magic_t magic;

	magic = magic_open(type);
	magic_load(magic, NULL);

	// Only looking at 1K max gives us a pretty substantial speed increase.
	// We'll do more comprehensive checks for potential positives.
	size_t length;
	if (quick) {
		length = std::min(contents_bytes.size(), (size_t)1024);
	} else {
		length = contents_bytes.size();
	}

	const char * magic_type_chr = magic_buffer(magic,
		contents_bytes.data(), length);
	std::string magic_type;

	if (magic_type_chr) {
		magic_type = magic_type_chr;
	} else {
		// Libmagic returned an error. Throw an appropriate exception (note that
		// there's a bug in libmagic that may make the error string NULL even if
		// an error was reported.)
		std::string error_msg;
		if (magic_error(magic)) {
			error_msg = magic_error(magic);
		} else {
			error_msg = "Known bug in libmagic";
		}
		throw std::logic_error("Libmagic: " + error_msg);
	}

	magic_close(magic);

	return magic_type;
}

std::string get_magic_mimetype(const std::vector<char> & contents_bytes) {
	try {
		return get_magic(contents_bytes, MAGIC_MIME_TYPE, true);
	} catch (std::logic_error & e) {
		return "application/x-unknown";
	}
}

std::string get_comprehensive_magic_mimetype(
	const std::vector<char> & contents_bytes) {

	try {
		return get_magic(contents_bytes, MAGIC_MIME_TYPE, false);
	} catch (std::logic_error & e) {
		return "application/x-unknown";
	}

}

std::string get_magic_encoding(const std::vector<char> & contents_bytes) {
	try {
		return get_magic(contents_bytes, MAGIC_MIME_ENCODING, true);
	} catch (std::logic_error & e) {
		return "application/x-unknown";
	}
}

std::vector<char> substr(const std::vector<char> & str, int start, int end) {
	return std::vector<char>(str.begin()+start, str.begin()+end);
}

std::vector<char> byte_seq(const char * what, int length) {
	return std::vector<char>(what, what+length);
}

std::vector<char> vecs(std::string what) {
	return std::vector<char>(what.begin(), what.end());
}

// Return a lowercased version of a string or substring.
std::string lower(std::string::const_iterator start, std::string::const_iterator stop) {
	std::string out;

	std::transform(start, stop, std::back_inserter(out),
		[](unsigned char c){ return std::tolower(c); });

	return out;
}

std::string to_str(const std::vector<char> & in) {
	return std::string(in.data(), in.data()+in.size());
}

// Produces a printable version of some arbitrary iterable structure, with
// printable letters preserved, newlines turned into spaces, and everything
// else turned into _.

// Do not use on very large texts; it's slow.

char printable_transform(char in) {
	if(in > 0x1F && in < 0x7F) { // printable letters; faster than isprint
		return in;
	}
	if (in == '\n' || in == '\r') {
		return ' ';
	}

	return '_';
}

template<typename IterIn> std::string printable(IterIn start, IterIn stop) {
	std::string out(start, stop);

	for (auto pos = out.begin(); pos != out.end(); ++pos) {
		*pos = printable_transform(*pos);
	}

	return out;
}

std::string lower(const std::string & instr) {
	return lower(instr.begin(), instr.end());
}

bool str_contains(const std::string & haystack,
	const std::vector<std::string> & needles) {

	for (const std::string & needle: needles) {
		if (haystack.find(needle) != std::string::npos) {
			return true;
		}
	}

	return false;
}

bool str_contains(const std::string & haystack, std::string needle) {
	return haystack.find(needle) != std::string::npos;
}

// Given and index into a string corresponding to the start and end of a substring
// match, this returns the window number of characters to the left of this region.
// It also returns the whole word if there's a word (i.e. sequence bracketed by
// spaces) within the window. In addition, it runs the whole thing through
// a printable transform so that the output can be printed to screen.
std::string get_surrounding_text(const std::string & text,
	size_t start_pos, size_t stop_pos, size_t window, bool ellipses) {

	// Search for spaces
	bool found_space_fwd = false, found_space_bkwd = false;
	// the +1 is so that we handle if the search term itself
	// has a space. TODO: Deal more robustly with it (what if there
	// are multiple spaces in front?)
	auto excerpt_start = text.begin() + start_pos + 1,
		excerpt_stop = text.begin() + stop_pos;

	for (size_t i = 0; i < window && excerpt_stop != text.end() &&
		!found_space_fwd; ++i) {
		// Check if the next printable-transformed char is a space. If so, stop.
		if (printable_transform(*excerpt_stop) == ' ') {
			found_space_fwd = true;
		} else {
			++excerpt_stop;
		}
	}

	found_space_bkwd = false;
	for (size_t i = 0; i < window && excerpt_start != text.begin() &&
		!found_space_bkwd; ++i) {

		if (printable_transform(*(excerpt_start-1)) == ' ') {
			found_space_bkwd=true;
		} else {
			--excerpt_start;
		}
	}

	std::string excerpt = printable(excerpt_start, excerpt_stop);

	// Denote by ellipses that the match is only part of a word, if
	// ellipses are desired and the match is incomplete.
	if (ellipses && !found_space_bkwd && excerpt_start != text.begin()) {
		excerpt = "..." + excerpt;
	}
	if (ellipses && !found_space_fwd && excerpt_stop != text.end()) {
		excerpt += "...";
	}

	return excerpt;
}

// This function returns the empty string if the file is neither a ZZT nor
// Super ZZT file, "zzt" if it's a ZZT file, and "szt" if it's a Super ZZT file.
std::string zzt_szt_check(const std::vector<char> & contents_bytes,
	bool multiple_boards_reqd) {

	// ZZT identification is pretty easy. The file starts with either FF FF or
	// FE FF. Then's the number of boards, which can't be above 100, so hex
	// values ?? 00.

	// We try to check as few things as possible because a false negative is
	// worse than a false positive. We do check for a bunch of known false
	// positives, though.

	// XXX: Beware LSB/MSB stuff! This code is not endian-portable!

	if (contents_bytes.size() < 4) { return ""; }

	zzt_header possible_header;
	memcpy(&possible_header, contents_bytes.data(), sizeof(zzt_header));

	// The header's OK, and, although 100 is the hard limit on boards, I think
	// KevEdit can break this limit, so let's use 255.
	bool header_OK = (possible_header.magic == ZZT_HEADER_MAGIC ||
			possible_header.magic == SUPERZZT_HEADER_MAGIC) &&
		possible_header.boards < 255;

	if (multiple_boards_reqd) {
		header_OK &= possible_header.boards > 0;
	}

	if (!header_OK) {
		return "";
	}

	/* Handle some false positives: Creatures files are FF FF xx xx 08 00 b"Creature".
	   A ZZT file with only two boards *could* technically have this header, but the
	   player would have 29251 gems, so I think I can do this... */

	if (contents_bytes.size() >= 14) {
		// Test for a Creatures sequence. This is rather more complex than the
		// Python syntax...
		if (possible_header.magic == -1 && substr(contents_bytes, 4, 14) ==
			byte_seq("\x08" "\x00" "Creature", 10)) {
			return "";
		}
		// Check for InstallShield SETUP.INS code. These files have
		// 00 02 00 02 repeating at 0x10, which would correspond to every other
		// key acquired with each of them being set by nonzero byte 02; not
		// very realistic.
		if (substr(contents_bytes, 0x10, 0x18) ==
			byte_seq("\x00\x02\x00\x02\x00\x02\x00\x02", 8)) {
				return "";
		}
	}

	// Tie Fighter mission files (.TIE) have headers like this:
	//    Index   Type            TIE             ZZT             SZT
	//    0x00    INT16LE         -1              -1              -2
	//    0x02    INT16LE         NumFGs          NumBoards
	//    0x04    INT16LE         NumMessages     PlayerAmmo
	//    0x06    INT16LE         Reserved        PlayerGems
	//    0x08    char[7]                         PlayerKeys
	//    0x08    UINT8           Unknown1
	//    0x09    BOOL            Unknown2
	//    0x0A    BYTE            BriefingOff.
	//    0x0D    BOOL            CapturedOnEject
	//    0x0F    INT16LE                         PlayerHealth
	//    0x11    INT16LE                         PlayerBoard
	//    0x13    INT16LE                         PlayerTorches   Unused
	//    0x15    INT16LE                         TorchCycles     PlayerScore
	//    0x17    INT16LE                         EnergyCycles    Unused
	//    0x18    char[64][6]     EndMissionMessages
	//    0x19    INT16LE                         Unused          EnergyCycles
	//    0x1B    UINT8                                           WorldNameLen
	//    0x1B    INT16LE                         PlayerScore

	// http://www.empirereborn.net/subdomains/idmr/Resources//tie/Mission_TIE95.txt

	// Such a file has null-terminated alphanumeric strings at 0x18 and
	// multiples of 64. Since the padding seems to be NULL everywhere on the
	// samples I've got, we'll just check the entire region for anything but
	// printable and NUL. If there's nothing else, it's a TIE file.

	// TBD

	bool only_TIE_bytes = true;

	for (size_t i = 24; i < 408 && only_TIE_bytes; ++i) {
		if (i >= contents_bytes.size()) { continue; }
		only_TIE_bytes &= (isprint(contents_bytes[i]) || contents_bytes[i] == 0);
	}

	// Also check the start of the strings: at least one of them should be
	// strictly printable.
	if (only_TIE_bytes) {
		bool letter_found = false;
		for (size_t i = 24; i < 408 && !letter_found; i += 64) {
			if (i >= contents_bytes.size()) { continue; }
			letter_found |= isprint(contents_bytes[i]);
		}
		only_TIE_bytes = letter_found;
	}

	if (only_TIE_bytes) {
		return "";
	}

	// We've run out of false positives to check against. Determine if it's
	// ZZT or Super ZZT.

	if (possible_header.magic == ZZT_HEADER_MAGIC) { return "zzt"; }
	return "szt";
}

// RLE checker for is_brd. This returns the number of tiles with a too high
// element type when parsing contents_bytes from start_pos on for board_size
// tiles in total as the ZZT or Super ZZT RLE format.
// NOTE: It's not currently very good at transposition errors
// (deleted or inserted bytes).
int check_rle(const std::vector<char> & contents_bytes, size_t start_pos,
	int board_size, int max_element) {

	// Do a very rough RLE check because I'm getting so many false positives.
	// The RLE format is [count] [element] [color] starting at 0x035 for ZZT
	// and 0x3F for Super ZZT. The official element maxima are 53 for ZZT and 79
	// for Super ZZT, but ZZT can support blinking text too, bringing the total
	// value up to 61. So we count the number of tiles up to a total of 1500
	// (60x25) for ZZT or 7680 (96x80) for Super ZZT, and check how many tile
	// bytes are out of range. If there are more than 20 (arbitrary threshold)
	// then it's not a .brd file for that game type.

	size_t i, tilecount = 0;
	size_t wrong_bytes_count = 0;

	for (i = start_pos; tilecount < board_size & i < contents_bytes.size();
		i += 3) {

		unsigned int rle_count = (unsigned char)contents_bytes[i];
		if (rle_count == 0) {
			rle_count = 256; // ZZT quirk
		}
		tilecount += rle_count;
		if (contents_bytes[i+1] > max_element) {
			++wrong_bytes_count;
		}
	}

	return wrong_bytes_count;
}

bool is_brd(const std::vector<char> & contents_bytes,
	bool check_zzt, bool check_szt, int max_unknown_tiles) {

	if (!check_zzt && !check_szt) {
		throw std::logic_error("is_brd: Was told to "
			"neither check for ZZT nor SZT boards!");
	}

	// This is harder, but:

	// The first two bytes give the size of the board, which should be in the rough
	// range of the actual length of the contents. The contents chunk could be larger
	// if the web server appends junk to it, but it shouldn't have a size of say, zero.
	// Then comes the length of the board title, which should be shorter than 60 bytes.
	// That's about it; we can't say much about the RLE structure without dragging in
	// a whole interpreter...

	// Note that although the ZZT spec says that the board size should be signed (and
	// thus never exceed 32k), KevEdit will happily produce larger .BRD files.
	if (contents_bytes.size() < 53) { return false; }

	brd_header possible_header;
	memcpy(&possible_header, contents_bytes.data(), sizeof(brd_header));

	int max_title_length = 50;
	if (check_szt) {
		max_title_length = 60;
	}

	if (possible_header.board_size < 53 || (size_t)possible_header.board_size >
		contents_bytes.size()*2) { return false; }
	if (possible_header.title_length > max_title_length ||
		possible_header.title_length < 0) {
		return false;
	}

	// Test for ZZT
	if (check_zzt &&
		check_rle(contents_bytes, 0x35, 60*25, 61) <= max_unknown_tiles) {
		return true;
	}

	// Super ZZT
	if (check_szt &&
		check_rle(contents_bytes, 0x3F, 96*80, 79) <= max_unknown_tiles) {
		return true;
	}

	return false;
}

bool is_brd(const std::vector<char> & contents_bytes,
	bool check_zzt, bool check_szt) {
	// This can be used to tune false positives vs negatives.
	const int MAX_TILE_ERRORS = 20;

	return is_brd(contents_bytes, check_zzt, check_szt,
		MAX_TILE_ERRORS);
}

bool is_brd(const std::vector<char> & contents_bytes) {
	return is_brd(contents_bytes, true, true);
}

// MegaZeux
// https://github.com/Sembiance/dexvert/issues/2
// https://www.digitalmzx.com/fileform.html#world
// https://www.digitalmzx.com/fileform.html#encryption200
// Though it seems like password-protected MZX 1.xx files
// have the magic offset by one byte, at byte 42 instead of
// 41.

// Returns true if the magic value substring is found
// at contents_bytes[start_pos].
bool check_signature(const std::vector<char> & contents_bytes,
	const std::vector<char> & signature,
	size_t start_pos) {

	bool match = false;

	for (size_t i = 0; i < signature.size(); ++i) {
		if (i + start_pos >= contents_bytes.size()) {
			return false;
		}
		if (contents_bytes[i+start_pos] != signature[i]) {
			return false;
		}
	}

	return true;
}

bool check_signatures(const std::vector<char> & contents_bytes,
	const std::vector<std::vector<char> > & signatures,
	size_t start_pos) {

	for (const auto & signature: signatures) {
		if (check_signature(contents_bytes, signature,
			start_pos)) {
			return true;
		}
	}

	return false;
}

// Returns "application/x-mzx-world", "application/x-mzx-board" or
// "application/x-mzx-save" if the file is any of these, otherwise
// returns the empty string.
std::string get_mzx_type(const std::vector<char> & contents_bytes) {

	// First check if it's an MZX world.

	// Signatures/magic values for MegaZeux worlds. Let's be a bit
	// generous and allow M\x02 with any suffix even though only some
	// are strictly speaking MZX world signatures.
	std::vector<std::vector<char> > mzx_world_sigs = {
		vecs("MZX"), vecs("MZ2"), vecs("MZA"), vecs("M\x02")
	};

	if (contents_bytes.size() > 25 && contents_bytes[25] == 0) {
		// Unencrypted, so the signature is at 26.
		if (check_signatures(contents_bytes, mzx_world_sigs,
			26)) { return "application/x-mzx-world"; }
	} else {
		// Encrypted, so the signature is either at 41 or 42.
		// I can't be bothered to special-case it for MZX 1.xx.
		for (int offset: {41, 42}) {
			if (check_signatures(contents_bytes, mzx_world_sigs,
				offset)) {
				return "application/x-mzx-world";
			}
		}
	}

	// Now check for saves. Same thing, but the signature is
	// at the very start. Again be generous and allow MZS\x02
	// in full generality.

	// "MZSAV" is not listed in the source; that's an MZX 1.xx
	// save.

	std::vector<std::vector<char> > mzx_save_sigs = {
		vecs("MZSAV"), vecs("MZSV2"), vecs("MZXSA"),
		vecs("MZS\x02")
	};

	if (check_signatures(contents_bytes, mzx_save_sigs, 0)) {
		return "application/x-mzx-save";
	}

	// Finally, check for MZX board files. I don't know the signature
	// for MZX 1.0x: my experiments seem to suggest that it's 0x64 0x64,
	// but that could easily just be the viewport size.
	// TODO: Figure out how to detect MZX 1.xx boards. Until then
	// there is a known false negative problem here.
	std::vector<std::vector<char> > mzx_board_sigs = {
		vecs("\xFFMB2")
	};

	if (check_signatures(contents_bytes, mzx_board_sigs, 0)) {
		return "application/x-mzx-board";
	}

	return "";
}

// Censor all but printables, and turn into a string.
std::string byte_str(const std::vector<char> & byte_sequence) {
	std::string out_str;
	out_str.reserve(byte_sequence.size());

	for (size_t i = 0; i < byte_sequence.size(); ++i) {
		if (isprint(byte_sequence[i])) {
			out_str += byte_sequence[i];
		} else {
			out_str += '_';
		}
	}
	return out_str;
}

// For text files: Do a keyword search and return a string describing the interest
// produced by this text, or the empty string if there's nothing of interest.

class false_match_data {
	public:
		std::string false_match;
		int offset;

		false_match_data(std::string fm_in, int off_in) {
			false_match = fm_in; offset = off_in;
		}
};

// Text

std::string data_interest_text(const std::string & body_text, bool exclude_long_words,
	const std::vector<std::string> & interesting_words) {

	// Don't match "BZZT". Also don't match ZZTop. The offsets (second part of the
	// tuple) gives how many letters precede "ZZT" in the false match.
	// Don't match *azzt (Mazzter, Jazztones) or *uzzt (Fuzztones, Fuzztrio) either.
	// Or *izzt (Drizzt, wizzt). Or other explosion/fizzle sounds like fzzt or ZZZT,
	// e.g. from http://geocities.com/TimesSquare/Stadium/4740/eb2epi2.html.

	std::vector<false_match_data> false_matches = {
		false_match_data("ZZTop", 0), false_match_data("ZZZT", 1),
		false_match_data("BZZT", 1), false_match_data("izzt", 1),
		false_match_data("azzt", 1), false_match_data("uzzt", 1),
		false_match_data("fzzt", 1), false_match_data("EMZXPYEI", 1),
		false_match_data("WA5ZZT", 3)
	};

	// Do a search for interesting words. This is the naive O(n^2) algorithm,
	// fix later if req'd.

	// Info about the characters surrounding the match.
	std::string context = "", matching_part = "";

	bool matched = false;
	for (std::string word: interesting_words) {
		if (matched) { continue; }

		size_t substr_pos = body_text.find(word);
		while (substr_pos != std::string::npos && !matched) {
			// Check for false positives.
			matched = true;
			for (false_match_data fm: false_matches) {
				if (!matched) { continue; }
				// If searching for the substring would put us out
				// of bounds, skippity.
				if ((int)substr_pos < fm.offset ||
					substr_pos + fm.false_match.size() - fm.offset >
						body_text.size()) {
					continue;
				}

				// Check against the specified false match.
				// TODO? Change the signature of this or make a shorthand funct?
				matching_part = std::string(
					body_text.begin() + substr_pos - fm.offset,
					body_text.begin() + substr_pos - fm.offset +
					fm.false_match.size());

				if (lower(matching_part) == lower(fm.false_match)) {
					matched = false;
				}
			}

			// Discard very long words. We make use of the side effect that
			// get_surrounding_data will return a full word containing the match
			// if one exists inside the window length.
			// Very long words are unlikely to be real matches, and more likely
			// to be Base64 stuff or similar.
			if (exclude_long_words && matched) {
				std::string long_window = get_surrounding_text(body_text,
					substr_pos, substr_pos + word.size(), 30, false);
				if (long_window.size() > 25) {
					matched = false;
				}
			}

			if (matched) {
				matching_part = std::string(body_text.begin() + substr_pos,
					body_text.begin() + substr_pos + word.size());
				context = get_surrounding_text(body_text,
					substr_pos, substr_pos + word.size(), 4, true);
				return "keyword(" + matching_part + ", " + context +")";
			}

			substr_pos = body_text.find(word, substr_pos+1);
		}
	}

	return "";
}

// TODO: Case insensitive MegaZeux, somehow

std::string data_interest_text(const std::string & body_text, bool exclude_long_words) {

	// NOTE: space has been set to be required for lowercase zzt and mzx due to
	// false positives. (See below re. "must be a word", which would be a better
	// constraint.)
	// TODO: Consider/investigate whether this would produce some false negatives.
	// It currently breaks the tests. (I'm thinking "zzters" etc would be a problem,
	// besides the obvious implementation deficiency of "It's zzt." not matching even
	// though "zzt" is a word here.)
	std::vector<std::string> interesting_words = { "ZZT", "MZX", "zzt ", "mzx ",
		"MegaZeux" };

	return data_interest_text(body_text, exclude_long_words, interesting_words);
}

// If searching binaries, demand a space at the end of the word, except for
// MegaZeux. BLUESKY: Also allow space at the beginning of the word (hard to
// do currently and this shouldn't be my priority at the moment).
std::string data_interest_binary_text(const std::string & body_text,
	bool exclude_long_words) {

	std::vector<std::string> interesting_words = { "ZZT ", "MZX ", "zzt ", "mzx ",
		"MegaZeux"/*, " ZZT", " MZX", " zzt", " mzx"*/ };

	return data_interest_text(body_text, exclude_long_words, interesting_words);
}

// HTML

// Recursively check all text elements (NOTE: Not links or other tag elements.
// This is part of the spec!)

// TODO: If this is slow, consider that other HTML parser that I don't remember
// the name of at the moment.
std::string data_interest_html(xmlNode * branch_root) {

	xmlNode * current_node = NULL;

	// If there is no node here, exit.
	if (branch_root == NULL) {
		return "";
	}

	for (current_node = branch_root; current_node != NULL;
		current_node = current_node->next) {

		if(current_node->type == XML_TEXT_NODE) {
			std::string text_interest = data_interest_text(
				(char *)current_node->content, true);
			if (text_interest != "") {
				return text_interest;
			}
		}

		std::string subtree_interest = data_interest_html(current_node->children);
		if (subtree_interest != "") {
			return subtree_interest;
		}
	}

	return "";
}

// libxml2 takes bytes as input.
std::string data_interest_html(const std::vector<char> & contents_bytes) {

	// We don't need the encoding. Since we aren't examining the
	// links, we don't need a base URL either.
	htmlDocPtr doc = htmlReadMemory(
		contents_bytes.data(), contents_bytes.size(),
		NULL, get_magic_encoding(contents_bytes).data(),
		HTML_PARSE_RECOVER | HTML_PARSE_NOBLANKS | HTML_PARSE_NOERROR |
		HTML_PARSE_NOWARNING | HTML_PARSE_NONET);

	if (doc == NULL) {
		// TODO: Somehow signal error. C++ exceptions are generally too
		// slow and an adversarial server could make us produce an arbitrary
		// amount of them...
		return ""; // Error parsing document.
	}

	std::string interest_type = data_interest_html(xmlDocGetRootElement(doc));

	xmlFreeDoc(doc);	// Free the document we read.
	xmlCleanupParser();	// And free globals. (Should this be called once per,
						// or just once at the end of the program?)

	return interest_type;
}

// Lightly adapted from libarchive's simple archive reading example.
// TODO: Handle internal paths more gracefully (yuck). Also TODO: Handle corrupted
// ZIPs inside OK ZIPs without throwing an exception and bailing out.

// Something like...

const int PRI_KEYWORD = 1, PRI_EXTENSION = 2,
			PRI_CONTENT = 3, PRI_ERROR = -1000;

// Planned PRI_UNIQUE_CONTENT = 4 - for content that we haven't seen before.
// Or do that somewhere else???

// Auxiliary function for determining if something is valid UTF-8.
// Source: http://www.zedwood.com/article/cpp-is-valid-utf8-string-function

bool utf8_check_is_valid(const std::string & string) {
	int c,i,ix,n,j;
	for (i=0, ix=string.length(); i < ix; i++) {
		c = (unsigned char) string[i];
		//if (c==0x09 || c==0x0a || c==0x0d || (0x20 <= c && c <= 0x7e) ) n = 0; // is_printable_ascii
		if (0x00 <= c && c <= 0x7f) {
			n=0;    // 0bbbbbbb
		} else if ((c & 0xE0) == 0xC0) {
			n=1;    // 110bbbbb
		} else if (c==0xed && i<(ix-1) && ((unsigned char)string[i+1] & 0xa0)==0xa0) {
			return false;    //U+d800 to U+dfff
		} else if ((c & 0xF0) == 0xE0) {
			n=2;    // 1110bbbb
		} else if ((c & 0xF8) == 0xF0) {
			n=3;    // 11110bbb
		}
		//else if (($c & 0xFC) == 0xF8) n=4; // 111110bb //byte 5, unnecessary in 4 byte UTF-8
		//else if (($c & 0xFE) == 0xFC) n=5; // 1111110b //byte 6, unnecessary in 4 byte UTF-8
		else {
			return false;
		}
		for (j=0; j<n && i<ix; j++) { // n bytes matching 10bbbbbb follow ?
			if ((++i == ix) || (((unsigned char)string[i] & 0xC0) != 0x80)) {
				return false;
			}
		}
	}
	return true;
}

// Returns a 28 byte MSB char vector containing the SHA224 hash of the
// contents of contents_bytes.
std::vector<char> get_sha224_raw(const std::vector<char> & contents_bytes) {
	// NOTE: Assumes that vectors are consecutive in memory.
	std::vector<char> out(28);
	SHA224((const unsigned char *)contents_bytes.data(),
		contents_bytes.size(), (unsigned char *)out.data());
	return out;
}

std::string to_hex(const std::vector<char> & data) {
	std::ostringstream parser;

	parser << std::setfill('0') << std::hex;

	for (char x: data) {
		parser << std::setw(2) << (int)((unsigned char)x);
	}

    return parser.str();
}

std::string get_sha224(const std::vector<char> & contents_bytes) {
	return to_hex(get_sha224_raw(contents_bytes));
}

// secondary constructor of sorts
interest_data create_error_data(std::string error, std::string mime_type,
	std::string file_hash) {

	interest_data error_out(PRI_ERROR, "", mime_type, file_hash);
	error_out.error = error;

	return error_out;
}

interest_report data_interest_type(const std::string & file_path,
	std::string mime_type, const std::vector<char> & contents_bytes) {

	return data_interest_type(file_path, mime_type, contents_bytes,
		DEFAULT_RECURSION_LEVEL, true);
}

// TODO: Quick and dirty factory-ish thing, fix later

enum parser_type {PARSER_LIB7ZIP, PARSER_LIBARCHIVE};

std::unique_ptr<archive_parser> generate_parser(parser_type type) {
	switch(type) {
		case PARSER_LIB7ZIP: return std::make_unique<lib7zip_parser>();
		case PARSER_LIBARCHIVE: return std::make_unique<libarchive_parser>();
		default: throw std::logic_error("Unknown parser type!");
	}
}

// parse_type is the archive parser type that's being used.
// file_path is the pathname to the archive.
// mime_type is the mimetype of the archive.
// contents_bytes is its contents.
// recursion level is the current recursion level, used to prevent
// things like zip bombs.
interest_report data_interest_archive(parser_type parse_type,
	const std::string & file_path, std::string mime_type,
	const std::vector<char> & contents_bytes, int recursion_level) {

	interest_report interesting_files;

	if (recursion_level <= 0) { return interesting_files; }

	std::unique_ptr<archive_parser> parse = generate_parser(
		parse_type);

	parse->read_archive(file_path, contents_bytes);

	std::runtime_error inherited_exception("placeholder");
	bool got_exception = false;

	read_state header_status = AP_OK;
	std::string error_msg;

	std::string archive_hash = get_sha224(contents_bytes);

	while (header_status != AP_ERROR && header_status != AP_DONE) {

		header_status = parse->read_next_header();

		if (header_status == AP_SKIP) {
			error_msg = "Error reading header from archive " +
				file_path + ": " + parse->get_error();
			interesting_files += create_error_data(
				error_msg, mime_type, archive_hash);
			continue;
		}

		if (header_status == AP_ERROR || header_status == AP_DONE) {
			continue;
		}

		interest_report interesting_in_file;
		bool decompression_failure = false;

		std::string inner_pathname = parse->entry_pathname;

		// Avoid ZIP bombs and other very large files. (32M max)
		if (parse->entry_file_size > (1<<25)) { continue; }

		std::vector<char> unpacked_bytes;
		int bytes_read = parse->uncompress_entry(unpacked_bytes);

		// Check if the compression method is supported. If not, insert
		// an error to this effect.
		if (bytes_read < 0) {
			decompression_failure = true;
			interesting_in_file += create_error_data(parse->get_error(),
				"application/x-unknown", "???");
			// Try anyway :-) Maybe the corruption is not so bad and we
			// can still recognize something.
		}

		std::string file_and_inner = file_path + "/" + inner_pathname;

		try {
			if (decompression_failure) {
				// Propagate a mime-type telling the function that we don't
				// know what the file is because we couldn't decompress it.
				interesting_in_file += data_interest_type( file_and_inner,
					"application/x-unknown", unpacked_bytes,
					recursion_level-1, false);
			} else {
				interesting_in_file += data_interest_type( file_and_inner,
					"", unpacked_bytes, recursion_level-1, true);
			}
		} catch (const std::runtime_error & e) {
			// If we got an exception, the rule is: if we find something else that's
			// interesting, forget it happened; but if we don't find anything, then
			// propagate it up, because the corrupt archive might have been
			// interesting.
			inherited_exception = e;
			got_exception = true;
		}

		// If we didn't find anything, but the file has the right extension, report
		// interest from the extension itself, as we're a bit more lenient here than
		// with uncompressed files. (XXX: Why? I think it's because the file may
		// be corrupted.)
		if (interesting_in_file.results.empty()) {
			std::string extension = lower(file_and_inner.begin() +
				file_and_inner.size() - 4, file_and_inner.end());
			if (str_contains(extension, { ".zzt", ".brd", ".mzx", ".mzb", ".szt",
				".zzm", ".zzl", ".zz3"})) {
				std::string magic_mime_type = get_magic_mimetype(unpacked_bytes);

				// If we got an extraction failure earlier, display an
				// unknown mime type instead of x-empty.
				if (decompression_failure) {
					magic_mime_type = "application/x-unknown";
				}

				interesting_in_file += interest_data(PRI_EXTENSION,
					"extension", magic_mime_type, "???");
			}
		}

		// Append the path to the archive to the interest data so that whatever
		// is calling us will know where the interesting files are stored. Also
		// set the archive bit and push the interest data to interesting_files.

		for (interest_data & id: interesting_in_file.results) {
			id.archive = true;

			if (id.internal_path == "") {
				id.internal_path = inner_pathname;
			} else {
				id.internal_path = inner_pathname + "/" + id.internal_path;
			}
		}

		// Writing a zip() routine just for this seems like overkill, so have some
		// cut and paste code instead.
		for (interest_data & id: interesting_in_file.errors) {
			id.archive = true;

			if (id.internal_path == "") {
				id.internal_path = inner_pathname;
			} else {
				id.internal_path = inner_pathname + "/" + id.internal_path;
			}
		}

		interesting_files += interesting_in_file;
	}

	if (header_status == AP_ERROR) {
		error_msg = "Error reading from archive " + file_path + ": " +
			parse->get_error();

		interesting_files += create_error_data(
			error_msg, mime_type, archive_hash);
		return interesting_files;
	}

	if (interesting_files.results.empty() && got_exception) {
		throw(inherited_exception);
	}

	return interesting_files;
}

// recursion_level is used internally (see data_interest_archive).

// TODO: Return three values: the path to the file that's interesting,
// the way it's interesting, and any potential errors. Perhaps also a bool
// denoting whether it *is* interesting.

interest_report data_interest_type(const std::string & file_path,
	std::string mime_type, const std::vector<char> & contents_bytes,
	int recursion_level, bool file_ok) {

	std::string magic_mime_type = get_magic_mimetype(contents_bytes);
	std::string hash;
	if (file_ok) {
		hash = get_sha224(contents_bytes);
	} else {
		hash = "???";
	}

	if (mime_type == "") {
		mime_type = magic_mime_type;
	}

	std::string extension = lower(file_path.begin() + file_path.size() - 4,
		file_path.end());

	// If it has the proper extension for files we can't verify the contents
	// of, that's interesting.
	if (str_contains(extension, { ".zz3", ".zzl", ".zzm" })) {
		return interest_data(PRI_EXTENSION, "extension", mime_type, hash);
	}

	std::string szt_zzt;

	// ZZT save files are denoted .SAV and are really just ZZT files. Check
	// for them. (BLUESKY: also check MegaZeux saves, which share the extension).
	// TODO: move a bunch of the string to interest data stuff to the internal
	// functions.
	if (str_contains(extension, { ".szt", ".zzt", ".sav"})) {
		szt_zzt = zzt_szt_check(contents_bytes, false);
	} else {
		szt_zzt = zzt_szt_check(contents_bytes, true);
	}

	if (szt_zzt != "") { return interest_data(PRI_CONTENT, szt_zzt,
		"application/x-zzt-world", hash); }

	// BRD file, always check. This is sufficiently prone to false positives
	// that we only check with the correct extension.
	if (str_contains(extension, ".brd")) {
		// Having some trouble with false positives, so remove
		// obvious offenders: picture files and HTML files.
		std::vector<std::string> false_pos = {"audio/", "video/", "image/",
				"text/html"};
		if (str_contains(magic_mime_type, false_pos)) {
			std::string comp_mime_type =
				get_comprehensive_magic_mimetype(contents_bytes);
			if (str_contains(comp_mime_type, false_pos)) {
				return {};
			}
		}

		if (is_brd(contents_bytes)) {
			return interest_data(PRI_CONTENT, "brd",
				"application/x-zzt-brd", hash);
		}
	}

	// Check for MegaZeux
	if (str_contains(extension,
		std::vector<std::string>({ ".mzx", ".mzb", ".sav"}))) {

		std::string possible_mzx_type = get_mzx_type(contents_bytes);
		if (possible_mzx_type != "") {
			return interest_data(PRI_CONTENT, "megazeux",
				possible_mzx_type, hash);
		}
	}

	// Don't check images, audio files or video files.
	if (str_contains(mime_type, {"audio/", "video/", "image/"})) {
		return {};
	}
	// Or Shockwave Flash files
	if (str_contains(mime_type, "application/x-shockwave-flash")) {
		return {};
	}

	// TODO: XML?
	if (str_contains(mime_type, "html")) {
		std::string possible_interest = data_interest_html(contents_bytes);
		if (possible_interest != "") {
			return interest_data(PRI_KEYWORD, possible_interest, mime_type,
				hash); }
	}

	// Stringify the contents so we can search it with data_interest_text.
	// TODO: make the latter work directly on the vectors.
	std::string contents_text = to_str(contents_bytes);

	if (str_contains(mime_type, "text/")) {
		// Text stuff goes here. Since all our search terms are pure ASCII,
		// there's no need for Unicode shenanigans (yet).
		std::string possible_interest = data_interest_text(contents_text, true);
		if (possible_interest != "") {
			return interest_data(PRI_KEYWORD, possible_interest, mime_type,
				hash);
		}
	}

	/* TODO: These are supported by lib7zip:
	001 7z a apm ar arj bz2 bzip2 cab chi chm chq chw cpio cramfs deb dll dmg doc docx elf
	epub esd exe ext ext2 ext3 ext4 fat flv gpt gz gzip hfs hfsx hxi hxq hxr hxs hxw ihex
	img iso jar lha lib lit lzh lzma lzma86 macho mbr msi mslz msp mub nsis ntfs ods odt ova
	pkg pmd ppt qcow qcow2 qcow2c r00 rar rpm scap squashfs swf swm sys tar taz tbz tbz2 te
	tgz tpz txz udf uefif vdi vhd vmdk wim xar xls xlsx xpi xz z z01 zip zipx.
	Some of them are probably also supported by libarchive. In any case, update the
	lists below to account for them. */


	// I think I've got all the formats libarchive supports -- except mtree and zip.uu.
	// NOTE: Apparently libarchive doesn't support .arj or .arc; I'm going to keep them
	// here for now so that they auto-register as corrupted (and I can check them manually
	// if need be).
	std::vector<std::string> archive_mimetypes = {
		"application/zip", "application/gzip", "application/x-tar", "application/x-arj",
		"application/x-lzh-compressed", "application/x-rar", "application/x-cpio",
		"application/x-iso9660-image", "application/vnd.ms-cab-compressed",
		"application/x-archive", "application/x-bzip2", "application/x-lz4",
		"application/x-lzop", "application/x-7z-compressed", "application/x-xz"
	};

	std::vector<std::string> archive_extensions = {".zip", ".gz", ".tar", ".arj",
		".lzh", ".rar", ".cpio", ".iso", ".cab", ".ar", ".bz2", ".lz4",
		".lzo", ".lzop", ".lzs", ".lzw", ".7z", ".xz"
	};

	// These can be archives, but also have other uses: don't count corrupt results
	// against it. This list is mainly dos executables (self-extracting archives).
	std::vector<std::string> possible_archive_mimetypes = {
		"application/x-dosexec", "application/octet-stream",
	};

	std::vector<std::string> possible_archive_extensions = { ".exe" };

	// If it's an archive, test separately.
	bool archive = str_contains(mime_type, archive_mimetypes) ||
		str_contains(magic_mime_type, archive_mimetypes) ||
		str_contains(extension, archive_extensions);
	bool maybe_archive = false;
	if (!archive) {
		maybe_archive = str_contains(extension, possible_archive_extensions);
	}

	// Empty files aren't archives.
	archive &= !contents_bytes.empty();

	interest_report interesting_in_file;

	// This currently only uses the lib7zip parser. I want to do the following
	// later; once it's done, I can make it check both lib7zip and libarchive:
	//	- Keep a track of every file that's been checked without error.
	//	- Skip decompressing files that have been checked without error before,
	//		unless they're archives (since delving further could give additional
	//		info.)
	//	- Retry files that led to errors; if we get something without error, then
	//		discard the errors. (e.g. libarchive gets something that's Imploded
	//		and lib7zip handles it properly.)
	//	- Memoize internal archive extraction so that e.g. "lib7zip extracts
	//		foo.zip, libarchive extracts foo.zip/bar.zip" vs "libarchive
	//		extracts both foo.zip and foo.zip/bar.zip" doesn't cause a
	//		combinatorial explosion.

	// One problem about this is that the capabilities may be different, e.g.
	// suppose libarchive can't open exe files' resource forks but lib7zip can;
	// and suppose there's an error in the exe file's resource fork; then naively
	// executing point three above would erase the legitimate errors. This can be
	// handled by only erasing errors for some given file (and marking it as
	// processed) if we can actually open that file without error. In the example
	// given, the resource fork virtual files wouldn't be opened at all by
	// libarchive and so their errors wouldn't be touched; but pulling this off
	// just right is going to take a bit of finagling.

	// These parsers should also report what formats they can handle so that if I
	// add lhasa later, it doesn't just blindly throw .zips etc. at it when it
	// can only handle LHA, LZH, and LZS.

	if (archive || maybe_archive) {
		//for (parser_type type : {PARSER_LIB7ZIP, PARSER_LIBARCHIVE}) {
		for (parser_type type : {PARSER_LIB7ZIP}) {
			try {
				interesting_in_file += data_interest_archive(type,
					file_path, mime_type, contents_bytes, recursion_level);
			} catch (const std::runtime_error & e) {
				// Don't signal corrupt archive file for something that's primarily not
				// an archive. And don't signal anything if the file is actually text,
				// which happens pretty often when crawling web pages.
				std::string mime_category(magic_mime_type.begin(),
					magic_mime_type.begin() + magic_mime_type.find("/"));
				if (!maybe_archive && mime_category != "text") {
					interesting_in_file += create_error_data(
						std::string("Corrupt archive file: ") +
							e.what(), mime_type, hash);
				}
			}
		}

		if (!interesting_in_file.results.empty()) {
			return interesting_in_file;
		}
	}

	// If all else fails, look for keywords in the binary stream.
	// We append even though interesting_in_file may well be empty because
	// it may also contain some errors.
	// TODO: Don't call this if we checked a text or html file.
	std::string possible_interest = data_interest_binary_text(contents_text, true);
	if (possible_interest != "") {
		interesting_in_file += interest_data(PRI_KEYWORD,
			possible_interest, mime_type, hash); }

	// Finally, return extension checks for files that either we can't match
	// or that should have been matched before.
	if (str_contains(extension,
		std::vector<std::string>({".mzx", ".mzb"}))) {

		return interest_data(PRI_EXTENSION, "extension", mime_type, hash);
	}

	// SZT and ZZT are sufficiently rare extensions that we flag them even if
	// the above check doesn't trigger. This is useful for corrupted compressed
	// data or data compressed using an unsupported method such as Implode.
	if (str_contains(extension, std::vector<std::string>({ ".szt", ".zzt"}))) {
		// Don't check what looks like images, audio files or video files.
		if (str_contains(magic_mime_type, {"audio/", "video/", "image/"})) {
			return {};
		}
		return interest_data(PRI_EXTENSION, "extension", mime_type, hash);
	}


	return interesting_in_file;

}

std::string highest_priority_interest_type(const std::string & file_path,
	const std::string & mime_type, const std::vector<char> & contents_bytes) {

	interest_report interesting_files =
		data_interest_type(file_path, mime_type, contents_bytes, 3,
			true);

	int record_priority = INT_MIN;
	std::string recordholder = "";

	for (const interest_data & id: interesting_files.results) {
		if (!id.interesting() || id.priority < record_priority) {
			continue;
		}
		record_priority = id.priority;
		recordholder = id.str();
	}

	return recordholder;
}

// --- //

// WARNING: This reports errors as uninteresting even though they may be
// evidence of a false positive (corrupt archive that would contain
// something interesting if uncorrupted, e.g.)
bool is_data_interesting(std::string filename, std::string mime_type,
	const std::vector<char> & contents_bytes) {

	return !data_interest_type(filename, mime_type, contents_bytes).
		results.empty();
}

// TODO: Add more tests from Python

bool TEST_interesting() {
	std::vector<std::vector<char> > must_be_interesting = {
		vecs("I like ZZT!"),
		vecs("I like ZZTop and ZZT!"),
		vecs("ZZT is my favorite game"),
		vecs("ZZTers and MZXers welcome"),
		vecs("MZXers and zzters welcome"),
		vecs("I heard there's a game called zzt or something"),
		// TODO: Make this work (i.e. ZZT must be a word, but doesn't need
		// to be flanked by spaces)
		//vecs("I heard there's a game called zzt."),
		byte_seq("ladeda\x00" " ZZT \x00", 13)
	};

	std::vector<std::vector<char> > must_be_uninteresting = {
		vecs("I like ZZTop!"),
		vecs("Lyrics ZZTop Lyrics"),
		vecs("I LIKE ZZTOP!"),
		vecs("i like zztop."),
		vecs("It went BZZT!"),
		vecs("DRIZZT IS THE COOLEST DROW"),
		vecs("Jazztones"),
		vecs("Fuzztrio"),
		vecs("BUZZTHRILL"),
		vecs("BZZZT"),
		vecs("The explosion fizzled with a fzzt"),
		// High-entropy strings that sometimes appear in Blogspot HTML files.
		vecs("window['__wavt'] = 'AOuZoY5I4fZZTlyPDxtXnUDukaEWGpHwrQ:1632960341455';_Widget"),
		vecs("<br />RsJ4NMZXYyyEdGrVjPlaolMdrCDGfsmzNeLU8kcFmr24xU6Y4AZ4nVJ87gaR5pINT/RIV0zm"),
		// Very long string with match at the end, and at the beginning
		vecs("__________________________________________________mzx"),
		vecs("zzt_______________________________________________"),
		// Serial numbers found in the Geocities archive
		vecs("/FMD027877 pw/EMZXPYEI"),
		vecs("WA5ZZT") //Ham radio code
	};

	bool all_OK = true;

	for (std::vector<char> test_str: must_be_interesting) {
		if (!is_data_interesting("test.txt", "text/plain", test_str)) {
			std::cerr << "Test fail: " << std::string(test_str.begin(), test_str.end())
				<< " not interesting.\n";
			all_OK = false;
		}
	}

	for (std::vector<char> test_str: must_be_uninteresting) {
		// Test both plaintext and binary data. Nothing that's uninteresting for
		// text should be interesting for binary data!

		if (is_data_interesting("test.txt", "text/plain", test_str)) {
			std::cerr << "Test fail: " << std::string(test_str.begin(), test_str.end())
				<< " interesting.\n";
			all_OK = false;
		}

		if (is_data_interesting("test.dat", "text/html", test_str)) {
			std::cerr << "Test fail: " << std::string(test_str.begin(), test_str.end())
				<< " interesting.\n";
			all_OK = false;
		}
	}

	// HTML, etc goes here.

	return all_OK;
}
