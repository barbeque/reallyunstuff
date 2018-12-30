#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>

#define GET4(buffer, i) (int)((unsigned char)(buffer[i + 0]) << 24 | (unsigned char)(buffer[i + 1]) << 16 | (unsigned char)(buffer[i + 2]) << 8 | (unsigned char)(buffer[i + 3]))
#define GET2(buffer, i) (int)((unsigned char)(buffer[i + 0]) << 8 | (unsigned char)(buffer[i + 1]))

int main(int argc, char* argv[]) {
  // sanity checks
  unsigned char testbuf[] = {0xff, 0xff, 0xdd, 0xcc};
  assert(GET2(testbuf, 0) == 0x0000ffff);
  assert(GET4(testbuf, 0) == 0xffffddcc);

  // ok let's go
  if(argc < 2) {
	  printf("Need argument.\n"); return 2;
  }
  FILE* fp = fopen(argv[1], "rb");
  if(!fp) {
    fprintf(stderr, "Not found.\n");
    return 1;
  }
  fseek(fp, 0, SEEK_END);
  long filelen = ftell(fp);
  rewind(fp);

  char* bytes = (char*)malloc((filelen + 1) * sizeof(char));
  fread(bytes, filelen, 1, fp);
  fclose(fp);

  const char *match="StuffIt (c)1997-\xFF\xFF\xFF\xFF Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/\x0d\x0a";

  for(unsigned int i = 0; i < strlen(match); ++i) { if(bytes[i] != match[i] &&
  match[i] != '\xFF') { printf("Wrong character at %i %i vs. %i\n", i, bytes[i],
  match[i]); printf("%s\n", match); for(int j = 0; j < i; ++j) { printf(" "); }
  printf("^\n"); return 1; } }

  printf("Header OK, continuing...\n");

  int ip = 80; // skip ahead past header
  ip += 4; // skip ahead past ???
  int total_archive_size = GET4(bytes, ip);
  ip += 4;
  printf("Total archive size: %i\n", total_archive_size);
  int some_entry_offset = GET4(bytes, ip);
  ip += 4;
  printf("Some entry ??? offset: %i\n", some_entry_offset);
  int entries_in_root = GET2(bytes, ip);
  ip += 2;
  printf("# of entries in root: %i\n", entries_in_root);
  int first_entry_offset = GET4(bytes, ip);
  ip += 4;
  printf("First entry offset: %i\n", first_entry_offset);

  if(bytes[82] != 5) {
	  printf("SIT VERSION: something is wrong\n"); return 1;
	}

  unsigned char flags = bytes[83];
  printf("Flags = %x\n", flags);
  if(flags & 0x10) { printf("\tSkip 14 bytes\n"); } // doesn't matter...? we just jump to the first archive offset anyway
  if(flags & 0x20) { printf("\t0x20\n"); }
  if(flags & 0x40) { printf("\t0x40\n"); }
  if(flags & 0x80) { printf("\tEncrypted?\n"); }


  // decompress the first entry...
  ip = first_entry_offset;
  unsigned int sitid = GET4(bytes, ip);
  ip += 4;
  if(sitid != 0xA5A5A5A5) { printf("SIT ID wrong (%x)!\n", sitid); return 1; }
  unsigned char version = bytes[ip];
  ip += 1;
  printf("version %i\n", version);
  unsigned char unknown = bytes[ip]; // skip byte
  ip += 1;
  printf("??? %i\n", unknown);
  unsigned int header_size = GET2(bytes,ip);
  ip += 2;
  printf("header size %i\n", header_size);

  ip += 1; // skip byte

  unsigned char file_flags = bytes[ip]; ip += 1; // we'll need this later

  unsigned int creation_date = GET4(bytes, ip);
  ip += 4;
  printf("creation date = %u\n", creation_date);
  unsigned int modification_date = GET4(bytes, ip);
  ip += 4;
  printf("modified date = %u\n", modification_date);
  unsigned int offset_prev_entry = GET4(bytes, ip);
  ip += 4;
  printf("offset_prev_entry = %u\n", offset_prev_entry);
  unsigned int offset_next_entry = GET4(bytes, ip);
  ip += 4;
  printf("offset_next_entry = %u\n", offset_next_entry);
  unsigned int offset_dir_entry = GET4(bytes, ip);
  ip += 4;
  printf("offset_dir_entry = %u\n", offset_dir_entry);
  unsigned int filename_length = GET2(bytes, ip);
  ip += 2;
  printf("Filename length = %u\n", filename_length);
  unsigned int header_crc = GET2(bytes, ip);
  ip += 2;
  printf("Header CRC = %u\n", header_crc);
  unsigned int datafile_size = GET4(bytes, ip);
  ip += 4;
  printf("data file size = %u\n", datafile_size); // seems low
  unsigned int crunched_size = GET4(bytes, ip);
  ip += 4;
  printf("crunched size = %u\n", crunched_size);
  ip += 4; // skip old crc16

  printf("file flags: %x\n", file_flags);

  if(file_flags & 0x40) {
    // directory!!
    printf("\tIs a directory.\n");
    unsigned int number_of_files = GET2(bytes, ip);
    printf("\tDirectory has %i file(s)\n", number_of_files);
    if(datafile_size == 0xffffffff) {
      // not sure what's going on here
      printf("Stub entry detected. TODO\n"); return 1;
    }
  }
  else {
    unsigned char datamethod = bytes[ip]; ip += 1;
    unsigned char passlen = bytes[ip]; ip += 1;
    if(flags & 0x20 && datafile_size) { // encrypted
      printf("\tIs encrypted.\n");
      if(passlen != 5) { //SIT5_KEY_LENGTH
        printf("\tKey length is wrong. Unarchiver would have barfed here.\n");
        printf("TODO\n"); return 1; // the file we want isn't encrypted.
      }
    }
    else if(passlen) {
      printf("\tPasslen is non-zero (%x) despite not being encrypted. Unarchiver would have barfed at offset (%i).\n", passlen, (ip - 1));
      return 1; // This was wrong in my test file, but I fixed it and Unarchiver was still mad.
    }
  }

  // Now we can read the name.
  char* this_filename = (char*)malloc(filename_length); // does stuffit not null-terminate?
  strncpy(this_filename, &bytes[ip], filename_length);
  printf("filename = [%s]\n", this_filename);
}
