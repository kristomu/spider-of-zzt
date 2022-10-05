#include "zzt_interesting.cc"
#include <boost/python.hpp>
using namespace boost::python;

/*class TestClass {
	public:
		void print() const {
			std::cout << "Hello there." << std::endl;
		}
};

// Interfacing information
BOOST_PYTHON_MODULE(world) {
	class_<TestClass>("TestClass")
		.def("print", &TestClass::print);
}*/

// A simple wrapper to get as much of the job done with minimal fuss.
// I could export interest_data directly but I don't feel like I know
// libboost-python well enough.

class ZZTInterestChecker {
	public:
		interest_data returned;

		void check(const std::string & file_path,
			std::string mime_type, const object & contents_bytes) const;

		std::string str() const {
			return returned.str();
		}

		int get_priority() const {
			return returned.priority;
		}

		bool interesting() const {
			return returned.interesting();
		}

};

void ZZTInterestChecker::check(const std::string & file_path,
	std::string mime_type, const object & contents_bytes) const {

	// TODO: check that the object is actually bytes and throw
	// an exception otherwise.

	// For some bizarre reason, bytes - which are explicitly 0-255 in
	// Python - are exposed as ints. What gives??? And fate's irony
	// also sets a Python string as a sequence of chars! You'd expect
	// it to be the other way around...
	stl_input_iterator<int> begin(contents_bytes), end;

	std::vector<char> buffer(begin, end);

	for(int i: buffer) {
		std::cout << i << std::endl;
	}

	// TODO: Call zzt_interesting here.
}

BOOST_PYTHON_MODULE(zzt_interesting) {
	class_<ZZTInterestChecker>("ZZTInterestChecker")
		.def("check", &ZZTInterestChecker::check)
		.def("str", &ZZTInterestChecker::str)
		.def("get_priority", &ZZTInterestChecker::get_priority)
		.def("interesting", &ZZTInterestChecker::interesting);
}
