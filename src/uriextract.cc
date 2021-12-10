#include <set>
#include <vector>
#include <sstream>
#include <iostream>
#include <cstring>
#include <string>

#include <re2/re2.h>
#include <re2/set.h>

// For testing purposes.

std::vector<char> byte_seq(const char * what, int length) {
	return std::vector<char>(what, what+length);
}

std::vector<char> vec(const char * what) {
	return std::vector<char>(what, what+strlen(what));
}

// We'll optimize later.
std::vector<std::set<std::string> > match_regexes(
	const std::vector<std::string> & regexes, const std::string & haystack) {

	std::vector<std::set<std::string> > all_matches;
	std::string match;

	for (const std::string & regex: regexes) {
		// Do "(" + ... + ")" here instead of in the regex itself?
		re2::RE2 re2_matcher(regex);
		re2::StringPiece input(haystack);

		std::set<std::string> matches_this_regex;

		while (re2::RE2::FindAndConsume(&input, re2_matcher, &match)) {
			matches_this_regex.insert(match);
		}
		all_matches.push_back(matches_this_regex);
	}

	return all_matches;
}

// TODO, char instead of word, or multiple chars instead...
std::vector<std::string> split(const std::string & to_split, std::string word) {
	size_t start = 0, end = to_split.find(word);

	if (end == std::string::npos) {
		return std::vector<std::string>(1, to_split);
	}

	std::vector<std::string> parts;

	while (end != std::string::npos) {
		parts.push_back(to_split.substr(start, end-start));
		start = end+1;
		end = to_split.find(word, start);
	}

	if (start != std::string::npos && start != to_split.size()) {
		parts.push_back(to_split.substr(start));
	}

	return parts;
}

bool contains(const std::string & haystack, const std::string & needle) {
	return (haystack.find(needle) != std::string::npos);
}

std::vector<std::string> extract_uris_text(const std::vector<char> & contents_bytes,
	bool strip_tags, std::string default_scheme) {

	RE2::Set uri_regex_set(RE2::DefaultOptions, RE2::UNANCHORED);

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
		R"((?i)((https?|ftp|aol|gopher|telnet|ssh):/\S+))",
		// This regex detects mail, javascript, etc URIs without : or validation.
		R"((?i)((mailto:|aim:|tel:|sms:|javascript:|rdf:|news:)\S+))",
		// The regex detects mail addresses without a mailto. It's from a comment
		// on https://stackoverflow.com/a/41798661.
		// Modified to allow for + in the username part of the address, and [] for IP
		// addresses; and hacked to add : to also handle raw authenticated URLs.
		R"(([\w+\.-:]+@[\w\[+\.-]+(?:\.[\w\]]+)+))",
		// A more general URL matcher, even without the protocol.
		// From https://stackoverflow.com/a/50790119
		// Modified so that stuff like index.html#foo matches the whole thing,
		// and so that underscore is allowed in the netloc. It produces a lot
		// of false positives and so the results need serious filtering.
		R"((?:https?://?|ftp://?|gopher://?|telnet://?|ssh://?)?(?:(?:www\.)?(?:[\da-z\.-_]+)\.(?:[a-z]{2,6})|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))(?::[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?(?:/[\w\.-]*)*(/|#\w+)?)"
		// DOS paths, e.g. C:/FOO/BAR. TODO

	};

	std::string contents_str(contents_bytes.begin(), contents_bytes.end());

	std::vector<std::set<std::string> > all_matches = match_regexes(
		uri_regexes, contents_str);

	std::vector<std::string> uris;
	size_t i;

	// Handle simple :// and mailto URIs (without validation).
	for (i = 0; i < 2; ++i) {
		for (std::string match: all_matches[i]) {
			std::cout << "[I] Match: " << match << std::endl;

			if (strip_tags) {
				std::cout << "SPLIT:" << split(match, "#")[0] << std::endl;
				uris.push_back(split(match, "#")[0]);
			} else {
				uris.push_back(match);
			}
		}
	}

	// Handle email without mailto, e.g. foo@bar.com. TODO: Add a discerning email
	// discriminator like in Python to get rid of false positives. For now just dump
	// everything into the uris array
	for (std::string auth_or_email: all_matches[2]) {
		std::string username_part = split(auth_or_email, "@")[0];

		// It's probably an authenticated URL and the @ we picked up is
		// the username:password@host bit
		if (contains(username_part, ":")) {
			uris.push_back(default_scheme + "://" + auth_or_email);
			continue;
		}

		// TODO: More stringent email check.
		// TODO: TLD check if possible.

		// It's a mail address; add it with mailto:
		uris.push_back("mailto:" + auth_or_email);
	}

/*	while (re2::RE2::PartialMatch(re2::StringPiece("alfa@beta.com"), mail_auth_regex, &match)) {
		std::cout << "Hm." << std::endl;
	}*/

	return uris;
}

std::vector<std::string> extract_uris_text(const std::vector<char> & contents_bytes,
	bool strip_tags) {

	return extract_uris_text(contents_bytes, strip_tags, "https");
}

bool perform_test(const std::vector<std::string> & observed,
	const std::vector<std::string> & expected,
	const std::vector<std::string> & unwanted) {

	std::set<std::string> observed_set(observed.begin(), observed.end());

	for (std::string expected_str: expected) {
		if (observed_set.find(expected_str) == observed_set.end()) {
			std::cout << "Test fail: " << expected_str << " not found." << std::endl;
			//return false;
		}
	}

	for (std::string unwanted_str: unwanted) {
		if (observed_set.find(unwanted_str) != observed_set.end()) {
			std::cout << "Test fail: " << unwanted_str << " found." << std::endl;
			//return false;
		}
	}

	return true;
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

	std::vector<char> testset = vec(
		"la de da http://www.aol.com/ http://www.aim.com/test#hello "
		"mailto:hello@whoever.com aol://5863:126/mB:206090 durr men.da skjer "
		"jo dette http://www.aol.com/http://foo.bar.baz ftp://existing "
		"http://hello@whoever.com somethinghttp://example.com tel:+18005557631 "
		"something.or.other.dk/something/wherever <a href=\"http://www2.test.com/\"> "
		"<a href=\"https://www3.test.com/i#foo\"> present.dk "
		"ubiquit.ous menda.cious poly.glottal 192.168.0.1/index.html "
		"allowed@example.dk allowed@[192.168.0.1] rejected@192.168.0.1 "
		"donkey@ubiquit.ous HTTP://WWW.AOL.COM/ hTTp://www.aim.com "
		"http://www.stripreturns.com/\r 'http://enclosed_a.com' "
		"\"http://enclosed_b.com\" (http://enclosed_c.com} (ftp://ftp.example.com), "
		"(ssh://ssh.example.com) http:\\\\backslash.com http:/missed.one.com "
		"test.zip http://www.exa...com/example.zip http:///////www.slashes.com "
		"http:////.*[/?/&]q=cache[^/+]*[/+]([a-zA-Z0-9_/+%/-/./: "
		"http://.*looksmart.com//.*[/?/&]key=([a-zA-Z0-9_/+%/-/./: "
		"http://foo_bar.tripod.com/test.html http://example.com/ax.html), "
		"x];inst.select https://example.com/bx.html). //www.basehtml.com/foo.html "
		"c:/PathOne/NAME C:\\PathTwo\\NAME ftp://user1:password@example.com "
		"user:password@example.com http://example.com/page.htm\",\"id\":\"4\" "
		"http://[^/.]/.mydomain.com");

	std::vector<std::string> expected = {
		"http://www.aol.com/", "http://www.aim.com/test#hello",
		"mailto:hello@whoever.com", "aol://5863:126/mB:206090",
		"http://www.aol.com/http://foo.bar.baz", "ftp://existing",
		"http://hello@whoever.com", "http://example.com",
		"tel:+18005557631", "https://something.or.other.dk/something/wherever",
		"http://www2.test.com/", "https://www3.test.com/i#foo",
		"https://present.dk", "https://192.168.0.1/index.html",
		"mailto:allowed@example.dk", "mailto:allowed@[192.168.0.1]",
		"HTTP://WWW.AOL.COM/", "hTTp://www.aim.com", "http://www.stripreturns.com/",
		"http://enclosed_a.com", "http://enclosed_b.com", "http://enclosed_c.com",
		"ftp://ftp.example.com", "ssh://ssh.example.com", "http://backslash.com",
		"http://missed.one.com", "http://www.slashes.com",
		"http://foo_bar.tripod.com/test.html", "http://example.com/ax.html",
		"https://example.com/bx.html", "https://www.basehtml.com/foo.html",
		"file://c:/PathOne/NAME", "file://C:/PathTwo/NAME",
		"ftp://user1:password@example.com", "https://user:password@example.com",
		"http://example.com/page.htm"};

	std::vector<std::string> unwanted = {
		"https://ubiquit.ous", "https://menda.cious", "https://poly.glottal",
		"https://www3.test.com/i#foo\">", "mailto:donkey@ubiquit.ous",
		"https://ftp.example.com", "https://test.zip",
		"http://www.exa...com/example.zip",
		"http:////.*[/?/&]q=cache[^/+]*[/+]([a-zA-Z0-9_/+%/-/./:",
		"http://.*[/?/&]q=cache[^/+]*[/+]([a-zA-Z0-9_/+%/-/./:",
		"http://.*looksmart.com//.*[/?/&]key=([a-zA-Z0-9_/+%/-/./:",
		"https://.tripod.com/test.html", "//www.basehtml.com/foo.html",
		"https://allowed@example.dk", "http://example.com/page.htm\",\"id\":\"4"
	};

	return perform_test(extract_uris_text(testset, false),
		expected, unwanted);
}

int main() {
	if (!TEST_extract_uris_text()) {
		std::cout << "Failed: TEST_extract_uris_text" << std::endl;
		return -1;
	}

	return 0;
}