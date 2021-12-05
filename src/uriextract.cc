#include <vector>
#include <iostream>
#include <cstring>

// For testing purposes.

std::vector<char> byte_seq(const char * what, int length) {
	return std::vector<char>(what, what+length);
}

std::vector<char> vec(const char * what) {
	return std::vector<char>(what, what+strlen(what));
}


std::vector<std::string> extract_uris_text(const std::vector<char> & contents_bytes,
	bool strip_tags, std::string default_scheme) {

	return {"N/A"};
}

std::vector<std::string> extract_uris_text(const std::vector<char> & contents_bytes,
	bool strip_tags) {

	return extract_uris_text(contents_bytes, strip_tags, "https");
}


bool TEST_extract_uris_text() {
	bool first_test =
		extract_uris_text("http://www.t.com#test", true) == {"http://www.t.com"} &&
		extract_uris_text("http://www.t.com#test", false) == {"http://www.t.com#test"}
}

int main() {
}