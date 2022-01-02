#include "zzt_interesting.cc"

int main(int argc, char ** argv) {
	TEST_interesting();

	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " [filename]" << std::endl;
		return(-1);
	}

	for (int i = 1; i < argc; ++i) {
		// Skip over directories.
		if (!is_file(argv[i])) { continue; }

		//std::cerr << argv[i] << std::endl;
		std::vector<char> data = file_to_vector(argv[i]);
		std::vector<std::string> interests = data_interest_type(argv[i], "", data);
		for (std::string interest: interests) {
			std::cout << argv[i] << "\t" << interest << "\n";
		}
	}
}
