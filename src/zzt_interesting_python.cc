#include "zzt_interesting.cc"
#include <boost/python.hpp>
#include <boost/python/suite/indexing/vector_indexing_suite.hpp>
namespace py = boost::python;

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
		interest_report check(const std::string & file_path,
			std::string mime_type, const py::object & contents_bytes,
			int recursion_level) const;
};

interest_report ZZTInterestChecker::check(
	const std::string & file_path, std::string mime_type,
	const py::object & contents_bytes,
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
	py::stl_input_iterator<unsigned char> begin(contents_bytes), end;

	std::vector<char> buffer(begin, end);

	return data_interest_type(
		file_path, mime_type, buffer, recursion_level);
}

BOOST_PYTHON_MODULE(zzt_interesting) {
	// Python convention is to use camel case for class names.
	py::class_<std::vector<interest_data> >("InterestVector")
		.def(py::vector_indexing_suite<std::vector<interest_data> >());
	py::class_<interest_report>("InterestReport")
		.def_readonly("results", &interest_report::results)
		.def_readonly("errors", &interest_report::errors);
	py::class_<ZZTInterestChecker>("ZZTInterestChecker")
		.def("check", &ZZTInterestChecker::check);
	py::class_<interest_data>("InterestData")
		.def("is_error", &interest_data::is_error)
		.def_readonly("priority", &interest_data::priority)
		.def_readonly("mime_type", &interest_data::mime_type)
		.def("__str__", &interest_data::str);
}
