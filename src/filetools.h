#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <sys/stat.h>

bool is_file(std::string filename);

// Note: this will choke with extremely large files! I don't know how to
// deal with them yet.

std::vector<char> file_to_vector(std::string filename);