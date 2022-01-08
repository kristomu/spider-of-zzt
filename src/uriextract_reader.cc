#include "uriextract.cc"

#include <sys/stat.h>

// https://stackoverflow.com/questions/4553012
bool is_file(std::string filename) {
	struct stat path_stat;
	stat(filename.data(), &path_stat);
	return S_ISREG(path_stat.st_mode);
}

int main(int argc, char ** argv) {
	if (!TEST_extract_uris_text()) {
		std::cout << "Failed: TEST_extract_uris_text" << std::endl;
		return -1;
	}

	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " [filename]" << std::endl;
		return(-1);
	}

	for (int i = 1; i < argc; ++i) {
		// Skip over directories.
		if (!is_file(argv[i])) { continue; }

		std::vector<char> file_contents = file_to_vector(argv[i]);

		std::vector<std::string> urls = extract_uris_text(file_contents,
			true, "https");

		std::copy(urls.begin(), urls.end(),
			std::ostream_iterator<std::string>(std::cout, "\n"));
	}
}
