// An in-memory C7Zip input stream. Note that it stores the data itself;
// if that becomes a memory problem, replace it with an auto_ptr or
// something...

#include "memory_in_stream.h"

void mem_stream::set(std::string filename_in,
	std::vector<char> contents_in) {

	filename = filename_in;
	// Get extension.
	int separator_pos = filename.rfind(".");
	// TODO later, make guesses as to what kind of file it is.
	// Also check if p7zip can handle "wrong" extensions. Doesn't
	// seem to be a problem for the command line tool... maybe I'll
	// just assume some extension here.
	if (separator_pos == std::string::npos) {
		throw std::runtime_error("Could not find extension for file " + filename);
	}

	// Unicode transformation... a bit involved though
	wchar_t* temp_unicode_filename = new wchar_t[filename.size()-separator_pos];
	mbstowcs(temp_unicode_filename, filename.c_str() + separator_pos + 1,
		filename.size()-separator_pos - 1);
	m_strFileExt = wstring(temp_unicode_filename,
		temp_unicode_filename + filename.size()-separator_pos - 1);

	current_position = 0;
	contents_bytes = contents_in;

	delete[] temp_unicode_filename;
}

// Copy bytes_to_read bytes from the stream source to data, and
// set *processed_size to the number of bytes actually copied
// (in case the file isn't that long)
int mem_stream::Read(void * data, unsigned int bytes_to_read,
	unsigned int * processed_size) {

	size_t end_pos = std::min(contents_bytes.size(),
		current_position + bytes_to_read);
	size_t count = end_pos - current_position;

	char * dataout = (char *) data;
	size_t i;
	for (i = current_position; i < end_pos; ++i) {
		*dataout++ = contents_bytes[i];
	}

	std::copy(contents_bytes.begin() + current_position,
		contents_bytes.begin() + end_pos, (char *)data);

	current_position += count;

	if (processed_size != NULL) {
		*processed_size = count;
	}

	return 0;
}

// Seek to offset (either relative or absolute depending on the value
// of whence) and then set the given int pointer to the new position.
// If impossible (out of bounds), return some false value.
int mem_stream::Seek(__int64 offset, unsigned int whence,
	unsigned __int64 * new_position) {

	size_t pos;

	switch(whence) {
		case SEEK_SET:		// Absolute seek
			pos = offset;
			break;
		case SEEK_CUR:		// Relative to current pos
			pos = current_position + offset;
			break;
		case SEEK_END:		// Relative to the end
			pos = contents_bytes.size() + offset;
			break;
		default:			// Not recognized.
			throw std::logic_error("Seek called with unknown"
				" whence value");
	}

	if (pos <= contents_bytes.size()) {
		current_position = pos;

		if (new_position != NULL) {
			*new_position = pos;
		}
		return 0;
	}

	return 1;
}

int mem_stream::GetSize(unsigned __int64 * size) {
	if (size) {
		*size = contents_bytes.size();
	}
	return 0;
}