#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <sys/stat.h>

// https://stackoverflow.com/questions/4553012
bool is_file(std::string filename) {
	struct stat path_stat;
	stat(filename.data(), &path_stat);
	return S_ISREG(path_stat.st_mode);
}

// Note: this will choke with extremely large files! I don't know how to
// deal with them yet.

std::vector<char> file_to_vector(std::string filename) {
	if (!is_file(filename)) {
		throw std::runtime_error("file_to_vector: not a regular file: "
			+ filename);
	}

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