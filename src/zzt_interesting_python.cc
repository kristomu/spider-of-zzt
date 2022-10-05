#include "zzt_interesting.cc"
#include <boost/python.hpp>
#include <boost/python/suite/indexing/vector_indexing_suite.hpp>
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

		std::vector<interest_data> check(const std::string & file_path,
			std::string mime_type, const object & contents_bytes,
			int recursion_level) const;

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

std::vector<interest_data> ZZTInterestChecker::check(
	const std::string & file_path, std::string mime_type,
	const object & contents_bytes,
	int recursion_level) const {

	// TODO: check that the object is actually bytes and throw
	// an exception otherwise.

	// For some bizarre reason, bytes - which are explicitly 0-255 in
	// Python - are exposed as ints. What gives??? And fate's irony
	// also sets a Python string as a sequence of chars! You'd expect
	// it to be the other way around...
	// Apparently that was just a strange casting chain (unsigned char
	// can be cast to int but not char, so it casts to int and then
	// nopes out that it can't cast the int to char).
	stl_input_iterator<unsigned char> begin(contents_bytes), end;

	std::vector<char> buffer(begin, end);

	return data_interest_type(
		file_path, mime_type, buffer, recursion_level);
}

BOOST_PYTHON_MODULE(zzt_interesting) {
	// Python convention is to use camel case for class names.
	class_<std::vector<interest_data> >("InterestVector")
        .def(vector_indexing_suite<std::vector<interest_data> >())
    ;
	class_<ZZTInterestChecker>("ZZTInterestChecker")
		.def("check", &ZZTInterestChecker::check)
		.def("str", &ZZTInterestChecker::str)
		.def("get_priority", &ZZTInterestChecker::get_priority)
		.def("interesting", &ZZTInterestChecker::interesting);
	class_<interest_data>("InterestData")
		.def_readonly("priority", &interest_data::priority)
		.def_readonly("mime_type", &interest_data::mime_type)
		.def("__str__", &interest_data::str);
}
