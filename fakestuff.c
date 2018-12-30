#include <cstdio>
#include <cassert>

int main(int argc, char* argv[]) {
	FILE* o = fopen("fake.sit", "wb");

	// header
	fprintf(o, "StuffIt (c)1997-2019 Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/\x0d\x0a");
	assert(ftell(o) == 80);
	// append a blank u16 and then a u8 for version and then u8 for flags
	unsigned short blank = 0;
	fwrite(&blank, 2, 1, o);
	assert(ftell(o) == 82);
	unsigned char sit_version = 5;
	fwrite(&sit_version, 1, 1, o);
	// dunno what to do here yet
	unsigned char flags = 0x10; // was 0x10 in the original
	fwrite(&flags, 1, 1, o);

	// calculate total archive size...
	unsigned int empty = 0;
	fwrite(&empty, 4, 1, o); // FIXME

	// some entry ??? offset
	unsigned int who_knows = 114;
	fwrite(&who_knows, 4, 1, o);

	// number of entries in root
	unsigned short root_entries = 1;
	fwrite(&root_entries, 2, 1, o);

	// first entry offset
	unsigned int first_entry_offset = 114; // same as who_knows
	fwrite(&first_entry_offset, 4, 1, o);

	// pad 14 bytes like we said
	unsigned char pad_14_bytes = 0;
	fwrite(&pad_14_bytes, 1, 14, o);

	// now we should be in a position to write the *file* header
	int file_start = ftell(o);
	printf("fp = %i, first_entry_offset = %i\n", file_start, first_entry_offset);
	assert(file_start == first_entry_offset);

	unsigned int sit_id = 0xa5a5a5a5;
	fwrite(&sit_id, 4, 1, o);
	unsigned char version = 1;
	fwrite(&version, 1, 1, o);
	unsigned char unknown_1 = 0;
	fwrite(&unknown_1, 1, 1, o);
	unsigned short header_size = 70; // it's what it was before
	fwrite(&header_size, 2, 1, o);
	// pad byte
	unsigned char pad = 0;
	fwrite(&pad, 1, 1, o);
	// file flags
	unsigned char file_flags = 0;
	fwrite(&file_flags, 1, 1, o);
	// creation date
	unsigned int creation_date = 0;
	fwrite(&creation_date, 4, 1, o);
	// write it for modified date too
	fwrite(&creation_date, 4, 1, o);

	unsigned int offset_prev_entry = 0;
	fwrite(&offset_prev_entry, 4, 1, o);
	unsigned int offset_next_entry = 0;
	fwrite(&offset_next_entry, 4, 1, o);
	unsigned int offset_dir_entry = 0;
	fwrite(&offset_dir_entry, 4, 1, o);
	
	unsigned short filename_length = 18; // hack
	fwrite(&filename_length, 2, 1, o);

	unsigned short header_crc = 37692; // hack
	fwrite(&header_crc, 2, 1, o);

	unsigned int datafile_size = 845908;
	fwrite(&datafile_size, 4, 1, o);

	unsigned int crunched_size = 428314;
	fwrite(&crunched_size, 4, 1, o);

	unsigned short legacy_crc16 = 0;
	fwrite(&legacy_crc16, 2, 1, o);

	// file not dir
	unsigned char datamethod = 15; // arsenic
	fwrite(&datamethod, 1, 1, o);
	unsigned char passlen = 0;
	fwrite(&passlen, 1, 1, o);

	// now i think i can write the file contents
	const char* filename = "FastNet III-SE30.image";
	fwrite(filename, filename_length, 1, o);

	printf("Header ends at %i (expected %i)\n", ftell(o), file_start + header_size);

	fclose(o);
}
