// An in-memory C7Zip output stream.

#include "memory_out_stream.h"

// Seek to offset (either relative or absolute depending on the value
// of whence) and then set the given int pointer to the new position.
// If impossible (out of bounds), return some false value.
int mem_out_stream::Seek(__int64 offset, unsigned int whence,
	unsigned __int64 * new_position) {

	size_t pos;

	switch(whence) {
		case SEEK_SET:		// Absolute seek
			pos = offset;
			break;
		case SEEK_CUR:		// Relative to current pos
			pos = cur_pos - offset;
			break;
		case SEEK_END:		// Relative to the end
			pos = output_data.size() + offset;
			break;
		default:			// Not recognized.
			throw std::logic_error("Seek called with unknown"
				" whence value");
	}

	if (pos <= output_data.size()) {
		cur_pos = pos;

		if (new_position != NULL) {
			*new_position = pos;
		}
		return 0;
	}

	return 1;
}