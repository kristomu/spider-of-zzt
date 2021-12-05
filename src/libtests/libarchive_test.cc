#include <sys/types.h>

#include <sys/stat.h>

#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <vector>

static void extract(const char *filename)
{
	archive *a;
	archive_entry *entry;
	int r;

	a = archive_read_new();
	archive_read_support_filter_all(a);
	archive_read_support_format_all(a);
	r = archive_read_open_filename(a, filename, 10240); // Note 1

	if (r != ARCHIVE_OK)
		exit(1);

	while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
		std::cout << archive_entry_pathname(entry) << std::endl;
		size_t inner_file_size = archive_entry_size(entry);

		std::cout << inner_file_size << std::endl;
		std::vector<char> foo(inner_file_size);
		char * buff;
		int64_t offset;
		r = archive_read_data(a, foo.data(), inner_file_size);
		//archive_read_data_skip(a);  // Note 2
	}

	r = archive_read_free(a);  // Note 3
	if (r != ARCHIVE_OK)
		exit(1);
}

int main(int argc, char ** argv) {
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " [filename]" << std::endl;
		return(-1);
	}

	for (int i = 1; i < argc; ++i) {
		extract(argv[i]);
	}
}
