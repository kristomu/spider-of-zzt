// Profiling results: If I need to make this even faster:
//		- Use Hypermatch instead of RE2 (~80%)
//		- Use a reference to a string instead of an actual string
//			in split_any's results. (~20%)

// But I can't be bothered right now.

#include <set>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <string>

#include <re2/re2.h>
#include <re2/set.h>

#include "libvldmail/vldmail.h"
#include "cxxurl/url.hpp"

#include "resolved_host.h"

#include <libxml/HTMLparser.h> // HTML parsing (TODO: XML)

// For testing purposes.

std::vector<char> byte_seq(const char * what, int length) {
	return std::vector<char>(what, what+length);
}

std::vector<char> vec(const char * what) {
	return std::vector<char>(what, what+strlen(what));
}

// Return a lowercased version of a string or substring.
// Dupe of zzt_interesting.cc's
std::string lower(std::string::const_iterator start,
	std::string::const_iterator stop) {
	std::string out;

	std::transform(start, stop, std::back_inserter(out),
		[](unsigned char c){ return std::tolower(c); });

	return out;
}

std::string lower(const std::string & instr) {
	return lower(instr.begin(), instr.end());
}

class mass_re_match {
	public:
		 // For each regex, which strings match it
		std::vector<std::set<std::string> >	matches;

		// For each string, which regex it matched.
		std::vector<std::vector<bool> > which_re;
};

// This checks the haystack against all the regexes and returns the
// matches as well as information about which strings matched what.
mass_re_match match_regexes(
	const std::vector<std::string> & regexes,
	const std::vector<std::string> & haystacks) {

	std::string match;
	mass_re_match all_matches;
	all_matches.which_re = std::vector<std::vector<bool> > (haystacks.size(),
		std::vector<bool>(regexes.size(), false));
	all_matches.matches.resize(regexes.size());

	for (size_t regex_idx = 0; regex_idx < regexes.size(); ++regex_idx) {
		// Do "(" + ... + ")" here instead of in the regex itself?
		re2::RE2 re2_matcher(regexes[regex_idx]);

		for (size_t haystack_idx = 0; haystack_idx < haystacks.size();
			++haystack_idx) {

			re2::StringPiece input(haystacks[haystack_idx]);

			while (re2::RE2::FindAndConsume(&input, re2_matcher, &match)) {
				all_matches.matches[regex_idx].insert(match);
				all_matches.which_re[haystack_idx][regex_idx] = true;
			}
		}
	}

	return all_matches;
}

// Splits on any of the characters in chars. TODO? Return StringPiece instead?
std::vector<std::string> split_any(const std::string & to_split,
	std::string chars) {

	size_t start = 0, end = to_split.find_first_of(chars);

	if (end == std::string::npos) {
		return std::vector<std::string>(1, to_split);
	}

	std::vector<std::string> parts;

	while (end != std::string::npos) {
		parts.push_back(to_split.substr(start, end-start));
		start = end+1;
		end = to_split.find_first_of(chars, start);
	}

	if (start != std::string::npos && start != to_split.size()) {
		parts.push_back(to_split.substr(start));
	}

	return parts;
}

// Find the first iterator position that doesn't contain an unwanted
// character.
template<typename T> T first_wanted_char(T start_pos, T end_pos,
	std::string unwanted_chars) {

	T pos;

	for (pos = start_pos; pos != end_pos; ++pos) {
		bool has_unwanted = false;
		for (char x: unwanted_chars) {
			has_unwanted |= (*pos == x);
		}
		if (!has_unwanted) {
			return pos;
		}
	}
	return pos;
}

std::string lstrip(const std::string & to_strip, std::string unwanted_chars) {
	std::string::const_iterator first_wanted = first_wanted_char(to_strip.begin(),
		to_strip.end(), unwanted_chars);
	return std::string(first_wanted, to_strip.end());
}

std::string rstrip(const std::string & to_strip, std::string unwanted_chars) {
	return std::string(to_strip.begin(),
		first_wanted_char(to_strip.rbegin(), to_strip.rend(),
			unwanted_chars).base());
}

bool contains(const std::string & haystack, const std::string & needle) {
	return (haystack.find(needle) != std::string::npos);
}

// To reduce false positives, we need a list of valid TLDs.
std::set<std::string> get_valid_tlds() {
	// Use the IANA list: https://data.iana.org/TLD/tlds-alpha-by-domain.txt
	std::ifstream tlds("tlds-alpha-by-domain.txt");
	std::set<std::string> tlds_out;
	std::string tld;

	if (!tlds.is_open()) {
		throw std::runtime_error("uriextract: Error opening valid TLD list!");
	}

	while(std::getline(tlds, tld)) {
		tld = lower(tld);
		// But not "#" (comment) or .zip (too many false positives)
		if (!contains(tld, "#") && !contains(tld, "zip")) {
			tlds_out.insert(tld);
		}
	}

	return tlds_out;
}

std::string remove_all(std::string input, char to_remove) {
	std::string::const_iterator new_end = std::remove_if (
		input.begin(), input.end(), [to_remove](char & x) {
			return x == to_remove;});
	input.resize(new_end - input.begin());

	return input;
}

// Global variable, fix later once I wrap this up in a class. TODO
std::set<std::string> global_tlds = get_valid_tlds();
std::set<std::string> known_schemes = {
	"https", "http", "ftp", "aol", "gopher", "telnet", "ssh", "irc",
	"file", "mailto", "aim", "tel", "sms", "javascript", "rdf", "news",
	"nntp", "icq"};

bool has_valid_tld(const Url & url) {
	// TODO: Use the proper numeric IP check from resolved_host.
	// Returns true if the host is valid, false otherwise.
	std::string host = url.host();
	// CxxUrl sets path to the whole mail address if it's a mailto,
	// so if the host is empty, try using that.
	if (host.empty()) { host = url.path(); }
	std::string tld = *split_any(host, ".").rbegin();
	bool numeric = !tld.empty() && std::all_of(
		tld.begin(), tld.end(), isdigit);

	// If we have a numeric IP, check if it's actually an IP address.
	if (numeric) {
		resolved_host ip;
		numeric = ip.update_with_ip(host);
	}

	if (numeric) { return true; }

	// If the host begins in a period, it's not valid. Nor is it
	// valid if there's no period at all (may cause false negatives
	// for intranet sites). Empty hosts are de facto invalid (not even
	// lynx supports them).
	bool valid_name = !host.empty() &&
		host[0] != '.' &&
		contains(host, ".") &&
		global_tlds.find(lower(tld)) != global_tlds.end();

	return numeric || tld == "" || valid_name;
}

// https://stackoverflow.com/a/1323374
bool valid_netloc_char(char x) {
	std::string special_chars = "@-_.:[]";

	return (x >= 'A' && x <= 'Z') || (x >= 'a' && x <= 'z') ||
		(x >= '0' && x <= '9') ||
		(special_chars.find_first_of(x) != std::string::npos);
}

// Returns true if the CxxUrl exception is a known false positive:
//	- mailto: URIs with IP address says path is wrong
bool cxxurl_false_positive(const Url::parse_error & err,
	const std::string & url_str) {

	// This is ugly...
	std::string manual_scheme = split_any(url_str, ":")[0];

	// If it's a URL scheme that our general expression explicitly
	// detects, then it's not a false positive (because mailto is
	// not part of that expression).
	return lower(manual_scheme) == "mailto" &&
		contains(err.what(), "Path");
}

bool has_valid_netloc(const std::string & url_str) {
	re2:RE2 urls_with_hosts(R"((?i)((https?|ftp|gopher|telnet|ssh|irc):))");

	try {
		Url url(url_str);

		// If it's a URL that should have a host but doesn't, return false.
		if (re2::RE2::PartialMatch(url_str, urls_with_hosts)) {
			if (url.host() == "") {
				return false;
			}

			// If it has a host, check this host against either having a
			// valid TLD or being a valid IP. NOTE: This may falsely
			// discard intranet addresses (e.g. http://fserver1/).
			if (!has_valid_tld(url)) { return false; }
		}

		// If it's a mailto without a path, return false.
		if (url.scheme() == "mailto" && url.path() == "") {
			return false;
		}

		if (contains(url.host(), "..")) {
			return false;
		}
		for (char x: url.host()) {
			if (!valid_netloc_char(x)) {
				return false;
			}
		}
		return true;
	} catch (Url::parse_error & err) {
		return cxxurl_false_positive(err, url_str);
	}
}

std::vector<std::string> extract_uris_text(std::string contents_str,
	bool strip_tags, std::string default_scheme) {

	// We use five regular expressions for extracting URIs from text:
	// One that handles URIs with :// in them (https?, ftp, gopher, etc.)
	//		indiscriminately (thus picking up things like ftp://a@b.com/)
	// One that handles URIs with : in them (mailto, tel),
	// One that handles mail addresses without mailto:,
	// One that handles :// and raw hostnames,
	// And one that handles DOS paths (file URLs).

	// The regexes use :/ instead of :// so we can spot misspellings like
	// http:/www.example.com

	// Note that every RE2 regex that's not already in a capturing group must
	// have one, or it won't match anything.

	std::vector<std::string> uri_regexes = {
		// This regex detects URIs with :// in them without much validation
		R"((?i)((https?|ftp|aol|gopher|telnet|ssh|irc|file):/\S+))",
		// This regex detects mail, javascript, etc URIs without : or validation.
		R"((?i)((mailto:|mail:|aim:|tel:|sms:|javascript:|rdf:|news:|nntp:|icq:)\S+))",
		// The regex detects mail addresses without a mailto. It's from a comment
		// on https://stackoverflow.com/a/41798661.
		// Modified to allow for + in the username part of the address, [] for IP
		// addresses and multiple consecutive @s for common mistyped addresses;
		// and hacked to add : to also handle raw authenticated URLs.
		R"(([\w+\.-:]+@+[\w\[+\.-]+(?:\.[\w\]]+)+))",
		// A more general URL matcher, even without the protocol.
		// From https://stackoverflow.com/a/50790119
		// Modified so that stuff like index.html#foo matches the whole thing,
		// and so that underscore is allowed in the netloc. It produces a lot
		// of false positives and so the results need serious filtering.
		// TODO: Apparently doesn't work? Fix. DONE, I think
		R"(((?:https?://?|ftp://?|gopher://?|telnet://?|ssh://|irc://?)?(?:(?:www\.)?(?:[\da-z\.-_]+)\.(?:[a-z]{2,6})|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))(?::[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?(?:/[\w\.-]*)*(/|#\w+)?))"
	};

	// For turning the wrong number of slashes (e.g. http:////) into the right
	// number.
	re2::RE2 slash_fix(R"((https?|ftp|aol|gopher|telnet|ssh|irc):/+)");

	// Change \ to / for consistent DOS and Windows file:// tag handling, and for
	// fixing some misspelled URLs (e.g. http:\\www.example.com)
	std::replace(contents_str.begin(), contents_str.end(), '\\', '/');

	// Split the input string by delimiter characters. This serves two purposes:
	// first, to reduce the complexity of the regex matching engine, and second,
	// to extract links from surrounding cruft (e.g. quotes of a href tag).

	std::vector<std::string> content_chunks = split_any(contents_str, "><{} \"\n");

	// Performance: remove everything that doesn't contain : or .
	std::vector<std::string>::const_iterator new_end = std::remove_if (
		content_chunks.begin(), content_chunks.end(), [](std::string & x) {
			return x.find_first_of(":.") == std::string::npos;});
	content_chunks.resize(new_end - content_chunks.begin());

	mass_re_match all_matches = match_regexes(uri_regexes, content_chunks);

	std::set<std::string> uris;
	size_t i;

	// Handle simple :// and mailto URIs (without much validation). (REs 0 and 1)
	for (i = 0; i < 2; ++i) {
		for (std::string match: all_matches.matches[i]) {
			std::string uri;

			if (strip_tags) {
				uri = split_any(match, "#")[0];
			} else {
				uri = match;
			}

			// Fix single slash or multi-slash URLs
			if ((contains(uri, ":/") && !contains(uri, "://")) ||
				contains(uri, ":///")){

				RE2::Replace(&uri, slash_fix, R"(\1://)");
			}

			// Remove some leading characters I've seen in test sets.
			uri = lstrip(uri, "({");

			// Remove trailing apostrophes or quotes from string markers, and
			// some characters I've seen in test sets.
			uri = rstrip(uri, "})'\"");

			// Standardize DOS/Windows file:// URLs to be file:///path
			// if they don't have a hostname already.
			try {
				Url url(uri);
				std::string x = url.host();
			} catch (Url::parse_error & e) {
				RE2::Replace(&uri, "(?i)(file://)", "file:///");
			}

			// Change mail: to mailto:
			RE2::Replace(&uri, "(?i)(^mail:)", "mailto:");

			uris.insert(uri);
		}
	}

	// Handle email without mailto, e.g. foo@bar.com. (RE 2)
	for (std::string auth_or_email: all_matches.matches[2]) {
		std::string username_part = split_any(auth_or_email, "@")[0];

		// It's probably an authenticated URL and the @ we picked up is
		// the username:password@host bit
		if (contains(username_part, ":") && !contains(username_part, "mailto:")) {
			uris.insert(default_scheme + "://" + auth_or_email);
			continue;
		}

		// Collapse consecutive @ marks (happens sometimes, e.g. foo@@bar.com)
		RE2::Replace(&auth_or_email, "(@+)", "@");

		// Now check if it's actually a valid mail address. If not,
		// get outta here.

		std::wstring coerced_ascii_mail(auth_or_email.begin(),
			auth_or_email.end());

		valid_mail_t validator = validate_email(coerced_ascii_mail.data());
		if (validator.success == 0) {
			// Something's wrong.
			continue;
		}

		// Check the TLD if the mail address has a hostname (not an IP
		// address).
		if (!contains(auth_or_email, "[") && !contains(auth_or_email, "]")) {
			std::string tld = *split_any(auth_or_email, ".").rbegin(); // last entry

			// If it's got an invalid tld, skip
			if (global_tlds.find(lower(tld)) == global_tlds.end()) {
				continue;
			}
		}

		// If it contains only one of [ and ], it's also invalid.
		if (contains(auth_or_email, "[") ^ contains(auth_or_email, "]")) {
			continue;
		}

		// It's a mail address; add it with mailto:
		uris.insert("mailto:" + auth_or_email);
	}

	// Handle complex URLs (RE 3). These need additional checks because there
	// are so many false positives.
	for (std::string approx_url: all_matches.matches[3]) {
		if (strip_tags) {
			approx_url = split_any(approx_url, "#")[0];
		}

		// Fix single slash or multi-slash URLs
		if ((contains(approx_url, ":/") && !contains(approx_url, "://")) ||
			contains(approx_url, ":///")){
			RE2::Replace(&approx_url, slash_fix, R"(\1://)");
		}

		// Try to parse the URL using CxxUrl.
		Url url;
		std::string rerendered_url; // required because url is lazy

		try {
			url = Url(approx_url);
			rerendered_url = url.str(); // will trigger exception if corrupt
		} catch (Url::parse_error & e) {
			try {
				// If we failed to parse directly, the URL might be polluted
				// with [] that's being misinterpreted as an invalid IPv6
				// address. Strip those and try again.
				approx_url = remove_all(remove_all(approx_url, '['), ']');
				url = Url(approx_url);
				rerendered_url = url.str();
			} catch (Url::parse_error & e2) {
				continue;
			}
		} catch (Url::build_error & e) {
			continue;
		}

		// If we don't see any of the schemes that we know about, go ahead
		// and add one: either the default scheme or mailto depending on
		/// whether it's a mail address. This can't be just the schemes
		// that this regex matches, because it may be falsely matching
		// something that contains a URL of some other scheme (e.g. mailto)

		if (known_schemes.find(lower(url.scheme())) == known_schemes.end()) {
			// If the URL contains both @ and : it's probably a
			// user:password@example.com type URL, not an email.
			if (contains(rerendered_url, "@") &&
				!contains(rerendered_url, ":")) {

				// If the first char is @, it's probably not a valid
				// email.
				if (rerendered_url[0] == '@') { continue; }

				url.scheme("mailto");

				// Check for validity (ew, cut and paste...)
				std::wstring coerced_ascii_mail(rerendered_url.begin(),
					rerendered_url.end());

				valid_mail_t validator = validate_email(coerced_ascii_mail.data());
				if (validator.success == 0) {
					continue;
				}
			} else {
				// Appens the default scheme and :// because CxxUrl can't distinguish
				// "www.example.com/foo" as a relative path from as a URL without
				// a scheme. We assume the latter.
				approx_url = default_scheme + "://" + rerendered_url;
				// This might have caused too many slashes; fix if so.
				// TODO: file://
				RE2::Replace(&approx_url, slash_fix, R"(\1://)");
				url = approx_url;
			}

			try {
				rerendered_url = url.str();
			} catch (Url::parse_error & e) {
				// If one of CxxUrl's false positives happen, just
				// use approx_url.
				if (cxxurl_false_positive(e, approx_url)) {
					uris.insert(approx_url);
				}
				continue;
			}
		}

		// Now check the hostname for a valid TLD.
		// If it's got an invalid tld, skip
		if (!has_valid_tld(url)) { continue; }

		rerendered_url = lstrip(rerendered_url, "({");
		rerendered_url = rstrip(rerendered_url, "})'\"");

		uris.insert(rerendered_url);
	}

	// Handle DOS paths, e.g. C:/FOO/BAR.
	// We use slash as the directory delimiter even though DOS uses
	// backslash, because we'll flatten backslash to slash in preprocessing.
	// The list of legal characters is from https://stackoverflow.com/a/31976060
	// This has to be done separately because we have to exclude strings that
	// also match a URL, which woudl be a false positive (e.g.
	// http:/www.example.com would "match" a dos path of p:/www.example.com
	// otherwise.
	// Could I just do this by looking for :// instead, for great code
	// simplicity? IDK
	re2::RE2 dos_matcher(R"(([A-Za-z]:/[^<>:\"|?*]+))");
	re2::RE2 url_matcher(uri_regexes[0]);
	for (i = 0; i < content_chunks.size(); ++i) {
		// If this content chunk also matches a URL, then matching it against
		// a DOS path would probably lead to a false positive, so skip.
		if (all_matches.which_re[i][0]) { continue; }
		re2::StringPiece input(content_chunks[i]);
		std::string match;

		while (re2::RE2::FindAndConsume(&input, dos_matcher, &match)) {
			uris.insert("file:///" + match);
		}
	}

	// Dump the set to a vector and sort it: we used a set earlier so that we'll
	// only return unique URLs, and it's a good idea to make the data presentable.
	// Only copy valid URLs.

	std::vector<std::string> returned_uris;
	std::copy_if(uris.begin(), uris.end(), std::back_inserter(returned_uris),
		has_valid_netloc);
	std::sort(returned_uris.begin(), returned_uris.end());

	return returned_uris;
}

std::vector<std::string> extract_uris_text(const std::vector<char> &
	contents_bytes, bool strip_tags, std::string default_scheme) {

	std::string contents_str(contents_bytes.begin(), contents_bytes.end());

	return extract_uris_text(contents_str,strip_tags, default_scheme);
}

std::vector<std::string> extract_uris_text(std::string contents_str,
	bool strip_tags) {

	return extract_uris_text(contents_str, strip_tags, "https");
}


std::vector<std::string> extract_uris_text(const std::vector<char> & contents_bytes,
	bool strip_tags) {

	return extract_uris_text(contents_bytes, strip_tags, "https");
}

bool perform_test(const std::vector<std::string> & observed,
	const std::vector<std::string> & expected,
	const std::vector<std::string> & unwanted) {

	std::set<std::string> observed_set(observed.begin(), observed.end());
	bool success = true;

	for (std::string expected_str: expected) {
		if (observed_set.find(expected_str) == observed_set.end()) {
			std::cout << "Test fail: " << expected_str << " not found." << std::endl;
			success = false;
		}
	}

	for (std::string unwanted_str: unwanted) {
		if (observed_set.find(unwanted_str) != observed_set.end()) {
			std::cout << "Test fail: " << unwanted_str << " found." << std::endl;
			success = false;
		}
	}

	return success;
}

bool TEST_extract_uris_text() {
	bool first_test =
		extract_uris_text(vec("http://www.t.com#test"), true)
			== std::vector<std::string>({"http://www.t.com"}) &&
		extract_uris_text(vec("http://www.t.com#test foo"), false)
			== std::vector<std::string>({"http://www.t.com#test"}) &&
		extract_uris_text(vec("http://www.t.com http://www.q.com"), false)
			== std::vector<std::string>({"http://www.q.com", "http://www.t.com"});

	if (!first_test) {
		return false;
	}

	// Massive test set from Python. TODO: Split up and use a proper test
	// framework (probably googletest).

	// Stuff I've commented out relates to functionality I'd like to implement
	// but haven't done yet.

	std::vector<char> testset = vec(
		"la de da http://www.aol.com/ http://www.aim.com/test#hello "
		"mailto:hello@whoever.com aol://5863:126/mB:206090 durr men.da skjer "
		"jo dette http://www.aol.com/http://foo.bar.baz ftp://existing.com "
		"http://hello@whoever.com somethinghttp://example.com tel:+18005557631 "
		"something.or.other.dk/something/wherever <a href=\"http://www2.test.com/\"> "
		"<a href=\"https://www3.test.com/i#foo\"> present.dk "
		"ubiquit.ous menda.cious poly.glottal 192.168.0.1/index.html "
		"allowed@example.dk allowed@EXAMPLE.DK allowed@[192.168.0.1] "
		"rejected@192.168.0.1 donkey@ubiquit.ous HTTP://WWW.AOL.COM/ "
		" hTTp://www.aim.com http://www.stripreturns.com/\r 'http://enclosed_a.com' "
		"\"http://enclosed_b.com\" (http://enclosed_c.com} (ftp://ftp.example.com), "
		"(ssh://ssh.example.com) http:\\\\backslash.com http:/missed.one.com "
		"test.zip http://www.exa...com/example.zip http:///////www.slashes.com "
		"http:////.*[/?/&]q=cache[^/+]*[/+]([a-zA-Z0-9_/+%/-/./: "
		"http://.*looksmart.com//.*[/?/&]key=([a-zA-Z0-9_/+%/-/./: "
		"http://foo_bar.tripod.com/test.html http://example.com/ax.html), "
		"x];inst.select https://example.com/bx.html). //www.basehtml.com/foo.html "
		"c:/PathOne/NAME C:\\PathTwo\\NAME ftp://user1:password@example.com "
		"user:password@example.com http://example.com/page.htm\",\"id\":\"4\" "
		"http://[^/.]/.mydomain.com www.somewhere.com/xy:/not_this "
		"/2g0http://example.com/expected2 7?;.hot. ftp:// "
		"https://..../..fc https:?.xy http://mixed.name.and.ip.1/ "
		"ftp://ftp.example.com:/"
		//"ftp://www.example.com/split\n/by/newline "
		"http://musicknight. http://www.Halftrack "
		"http://www.sounddogs.comTCOP .05:@A90.6DIFCHH/ "
		"http://www.example.com:nonnumericport/ "
		"mailto:?@q.fe example@aol.com. (us.undernet.org:6667) "
		"http://com/ http://.com/ @example.com a@b.....com "
		"foo@bar[.com foo@bar].com bar@@example.com "
		"aim:leethaxor icq:1234567 file://c:/example.exe "
		"file://localhost/etc/passwd mail:almost_mailto@example.com "
		"=mailto:gratia@example.com 'mailto:gratia2@example.com' "
		"news:alt.games.descent nntp:alt.games.corewar");

	std::vector<std::string> expected = {
		"http://www.aol.com/", "http://www.aim.com/test#hello",
		"mailto:hello@whoever.com", "aol://5863:126/mB:206090",
		"http://www.aol.com/http://foo.bar.baz", "ftp://existing.com",
		"http://hello@whoever.com", "http://example.com",
		"tel:+18005557631", "https://something.or.other.dk/something/wherever",
		"http://www2.test.com/", "https://www3.test.com/i#foo",
		"https://present.dk", "https://192.168.0.1/index.html",
		"mailto:allowed@example.dk", "mailto:allowed@EXAMPLE.DK",
		"mailto:allowed@[192.168.0.1]", "http://www.aol.com/",
		"http://www.aim.com", "http://www.stripreturns.com/",
		"http://enclosed_a.com", "http://enclosed_b.com", "http://enclosed_c.com",
		"ftp://ftp.example.com", "ssh://ssh.example.com", "http://backslash.com",
		"http://missed.one.com", "http://www.slashes.com",
		"http://foo_bar.tripod.com/test.html", "http://example.com/ax.html",
		"https://example.com/bx.html", "https://www.basehtml.com/foo.html",
		"file:///c:/PathOne/NAME", "file:///C:/PathTwo/NAME",
		"ftp://user1:password@example.com", "https://user:password@example.com",
		"http://example.com/page.htm", "http://example.com/expected2",
		//"ftp://ftp.example.com/", "ftp://www.example.com/split/by/newline",
		"mailto:example@aol.com", "mailto:bar@example.com",
		"aim:leethaxor", "icq:1234567", "file:///c:/example.exe",
		"file://localhost/etc/passwd", "mailto:almost_mailto@example.com",
		"news:alt.games.descent", "nntp:alt.games.corewar"};

	std::vector<std::string> unwanted = {
		"https://ubiquit.ous", "https://menda.cious", "https://poly.glottal",
		"https://www3.test.com/i#foo\">", "mailto:donkey@ubiquit.ous",
		"https://ftp.example.com", "https://test.zip",
		"http://www.exa...com/example.zip",
		"http:////.*[/?/&]q=cache[^/+]*[/+]([a-zA-Z0-9_/+%/-/./:",
		"http://.*[/?/&]q=cache[^/+]*[/+]([a-zA-Z0-9_/+%/-/./:",
		"http://.*looksmart.com//.*[/?/&]key=([a-zA-Z0-9_/+%/-/./:",
		"https://.tripod.com/test.html", "//www.basehtml.com/foo.html",
		"https://allowed@example.dk", "http://example.com/page.htm\",\"id\":\"4",
		"https://www.somewhere.com/xy://not_this", "https://..../..fc",
		"https:?.xy", "http://mixed.name.and.ip.1/", "ftp://",
		/*"ftp://ftp.example.com:/",*/ "http://musicknight.",
		"http://www.Halftrack", "http://www.sounddogs.comTCOP",
		"https://.05:@A90.6DIFCHH", "http://www.example.com:nonnumericport/",
		"mailto:?@q.fe", "us.undernet.org:6667", "http://com/",
		"mailto:@example.com", "http://.com/", "mailto:a@b.....com",
		"mailto:foo@bar[.com", "mailto: foo@bar].com",
		"https://mailto:gratia@example.com",
		"https://mailto:gratia2@example.com"
	};

	return perform_test(extract_uris_text(testset, false),
		expected, unwanted);
}

// An idea here is to first dump all tags into a suitable data structure, and then
// do the equivalent of Python's findall on this data structure. But what should
// the data structure be? I'm thinking something like
// map of string (tag name) to
//		list of entries
//		each of which is a list of pairs of attributes and values.
// Although I could be inclined to make an entry a map from attribute to value, so
// that it would be easy to do something like if (contains(entry, "http-equiv"))
// similar to the Python version's get().

// Yeah, let's do that.

typedef std::map<std::string, std::string> tag_entry;
typedef std::map<std::string, std::vector<tag_entry> > html_tags;

std::vector<std::string> extract_uris_html(xmlNode * branch_root,
	const std::string & base_url, bool strip_tags) {

	xmlNode * current_node = NULL;
	std::vector<std::string> urls;

	// If there is no node here, exit.
	if (branch_root == NULL) {
		return urls;
	}

	// TODO: Handle tags properly

	for (current_node = branch_root; current_node != NULL;
		current_node = current_node->next) {

		std::vector<std::string> urls_from_node;

		// Check with tests if this returns what we want it to return..
		switch(current_node->type) {
			case XML_TEXT_NODE:
				urls_from_node = extract_uris_text(
					(char *)current_node->content, true);
				break;
			case XML_ELEMENT_NODE: // e.g. links or base tags
				std::cout << current_node->name << std::endl;
				if (std::string((const char *)current_node->name) == "a") {
					std::cout << "VF: " << xmlGetProp(current_node,
						(const xmlChar *)"href") << std::endl;
				}
				break;
		}

		std::copy(urls_from_node.begin(), urls_from_node.end(),
			std::back_inserter(urls));

		urls_from_node = extract_uris_html(current_node->children,
			base_url, strip_tags);

		std::copy(urls_from_node.begin(), urls_from_node.end(),
			std::back_inserter(urls));
	}

	return urls;
}

// TODO: Perhaps move this to a class as I'm doing pretty much the same thing
// in zzt_interesting too?
std::vector<std::string> extract_uris_html(const std::vector<char> & contents_bytes,
	std::string base_url_in, bool strip_tags) {

	// We don't need the encoding. Since we aren't examining the
	// links, we don't need a base URL either.
	htmlDocPtr doc = htmlReadMemory(
		contents_bytes.data(), contents_bytes.size(),
		// TODO: get_magic_recording should also be shared somehow...
		// perhaps in a document class. We'd need that anyway to centralize
		// concerns about trusting what the server says about the file format
		// vs what magic says, etc...
		NULL, "ascii", //get_magic_encoding(contents_bytes).data(),
		HTML_PARSE_RECOVER | HTML_PARSE_NOBLANKS | HTML_PARSE_NOERROR |
		HTML_PARSE_NOWARNING | HTML_PARSE_NONET);

	if (doc == NULL) {
		// TODO: Somehow signal error. C++ exceptions are generally too
		// slow and an adversarial server could make us produce an arbitrary
		// amount of them...
		return {}; // Error parsing document.
	}

	auto urls_from_doc = extract_uris_html(xmlDocGetRootElement(doc),
		base_url_in, strip_tags);

	xmlFreeDoc(doc);	// Free the document we read.
	xmlCleanupParser();	// And free globals. (Should this be called once per,
						// or just once at the end of the program?)

	// TODO: remove duplicate entries
	return urls_from_doc;
}

bool TEST_extract_uris_html() {
	std::string testing = R"(
		<META HTTP-EQUIV="Content-Type" CONTENT="text/html">
		<META HTTP-EQUIV="refresh" CONTENT="300; http://www.example.com/redirect.html">
		<a href="/slashdot.html">test</a>
		<img src="beta/gamma.html">
		<img srcset="http://www.example.com/test.png 480w">
		<img srcset="path/foobar.png 480w">
		Visit www.example.com if you dare.
		<div>http://www.example.com/coolcat.html</div>is cool.
		So is <div><a href="http://www.example.com/reallydone.html"></div>.)";

	std::vector<std::string> expected = {
		"http://www.example.com/redirect.html",
		"http://www.test.com/slashdot.html",
		"http://www.test.com/alphabetical/beta/gamma.html",
		"http://www.example.com/test.png",
		"http://www.test.com/alphabetical/path/foobar.png",
		"https://www.example.com",
		"http://www.example.com/coolcat.html",
		"http://www.example.com/reallydone.html"};

	std::vector<std::string> unwanted = {
		"http://www.test.com/alphabetical/text/html"
	};

	return perform_test(extract_uris_html(std::vector<char>(
			testing.begin(),testing.end()),
		"http://www.test.com/alphabetical/", true), expected, unwanted);
}


std::vector<char> file_to_vector(std::string filename) {
/*	if (!is_file(filename)) {
		throw std::runtime_error("file_to_vector: not a regular file: "
			+ filename);
	}*/

	std::ifstream in_file(filename, std::ios::binary);

	if (!in_file || in_file.fail()) {
		throw std::runtime_error("file_to_vector: can't open " + filename + ": "
			+ strerror(errno));
	}

	// Get the size of the file.
	std::streampos file_size;

	in_file.seekg(0, std::ios::end);
	file_size = in_file.tellg();
	in_file.seekg(0, std::ios::beg);

	// And then read the data.
	std::vector<char> file_contents(file_size);
	in_file.read(file_contents.data(), file_size);
	return file_contents;
}

void perftest() {
	std::vector<char> file_contents = file_to_vector("tests/slow2.html");

	for (int i = 0; i < 30; ++i) {
		std::vector<std::string> q = extract_uris_text(
			file_contents, true, "https");
	}
}

/*
int main() {
	if (!TEST_extract_uris_text()) {
		std::cout << "Failed: TEST_extract_uris_text" << std::endl;
		return -1;
	}

	// perftest();

	return 0;
}
*/