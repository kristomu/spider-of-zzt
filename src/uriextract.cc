#include <set>
#include <vector>
#include <sstream>
#include <iostream>
#include <cstring>
#include <string>

#include <re2/re2.h>

// For testing purposes.

std::vector<char> byte_seq(const char * what, int length) {
	return std::vector<char>(what, what+length);
}

std::vector<char> vec(const char * what) {
	return std::vector<char>(what, what+strlen(what));
}


std::vector<std::string> extract_uris_text(const std::vector<char> & contents_bytes,
	bool strip_tags, std::string default_scheme) {

	re2::RE2 simple_data_regex("((https?|ftp|aol|gopher|telnet|ssh):/\\S+)");

	std::string foo(contents_bytes.begin(), contents_bytes.end());
	re2::StringPiece input(foo);

	std::string a, b;

	std::vector<std::string> uris;

	if (re2::RE2::PartialMatch(input, simple_data_regex, &a)) {
		std::cout << "Match: " << a << std::endl;

		// TODO: FIX!
		std::istringstream iss(a);
		std::string without_tag;
		std::getline(iss, without_tag, '#');

		std::cout << "Without anchor: " << without_tag << std::endl;

		if (strip_tags) {
			uris.push_back(without_tag);
		} else {
			uris.push_back(a);
		}
	}

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
			return false;
		}
	}

	for (std::string unwanted_str: unwanted) {
		if (observed_set.find(unwanted_str) != observed_set.end()) {
			std::cout << "Test fail: " << unwanted_str << " found." << std::endl;
			return false;
		}
	}

	return true;
}

bool TEST_extract_uris_text() {
	bool first_test =
		extract_uris_text(vec("http://www.t.com#test"), true)
			== std::vector<std::string>({"http://www.t.com"}) &&
		extract_uris_text(vec("http://www.t.com#test"), false)
			== std::vector<std::string>({"http://www.t.com#test"});

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