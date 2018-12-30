#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>

#define GET4(buffer, i) (int)((unsigned char)(buffer[i + 0]) << 24 | (unsigned char)(buffer[i + 1]) << 16 | (unsigned char)(buffer[i + 2]) << 8 | (unsigned char)(buffer[i + 3]))
#define GET2(buffer, i) (int)((unsigned char)(buffer[i + 0]) << 8 | (unsigned char)(buffer[i + 1]))

char* bytes;
unsigned int ip;

#define SIT5_ID 0xA5A5A5A5

#define SIT5FLAGS_DIRECTORY     0x40
#define SIT5FLAGS_CRYPTED       0x20
#define SIT5FLAGS_RSRC_FORK     0x10

#define SIT5_ARCHIVEVERSION 5

#define SIT5_ARCHIVEFLAGS_14BYTES 0x10
#define SIT5_ARCHIVEFLAGS_20      0x20
#define SIT5_ARCHIVEFLAGS_40      0x40
#define SIT5_ARCHIVEFLAGS_CRYPTED 0x80

#define SIT5_KEY_LENGTH 5  /* 40 bits */

const char* get_name_of_method(int stuffit_method) {
  switch(stuffit_method) {
    case 15:
      return "Arsenic";
    default:
      return "Dunno";
  }
}

void parseWithNumberOfTopLevelEntries(int number_of_entries) {
  for(int i = 0; i < number_of_entries; ++i) {
    printf("== ENTRY %i ==\n", i);

    unsigned int number_of_files_in_dir = 0; // HACK
    unsigned char datamethod = 0;

    // decompress the entry...
    unsigned int start_offset = ip;

    unsigned int sitid = GET4(bytes, ip);
    ip += 4;
    if(sitid != SIT5_ID) { printf("ip = %i SIT ID wrong (%x)!\n", (ip - 4), sitid); exit(1); }
    unsigned char version = bytes[ip];
    ip += 1;
    printf("version %i\n", version);
    unsigned char unknown = bytes[ip]; // skip byte
    ip += 1;
    printf("??? %i\n", unknown);
    unsigned int header_size = GET2(bytes,ip);
    ip += 2;
    printf("header size %i\n", header_size);
    unsigned int header_end = start_offset + header_size; // will need to fix this for multifile

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
    unsigned int stuffItCRC16 = GET2(bytes, ip);
    ip += 2;
    printf("Stuffit CRC16 = %i\n", stuffItCRC16);
    ip += 2; // skip the 2-byte thing after it

    printf("file flags: %x\n", file_flags);

    if(file_flags & SIT5FLAGS_DIRECTORY) {
      // directory!!
      printf("\tIs a directory.\n");
      number_of_files_in_dir = GET2(bytes, ip);
      ip += 2;
      printf("\tDirectory has %i file(s)\n", number_of_files_in_dir);

      if(datafile_size == 0xffffffff) {
        // not sure what's going on here - some kind of spacer entry?
        printf("Stub entry detected. TODO\n"); exit(1);
      }
    }
    else {
      datamethod = bytes[ip]; ip += 1;
      unsigned char passlen = bytes[ip]; ip += 1;
      if(file_flags & SIT5FLAGS_CRYPTED && datafile_size) { // encrypted
        printf("\tIs encrypted.\n");
        if(passlen != 5) { //SIT5_KEY_LENGTH
          printf("\tKey length is wrong. Unarchiver would have barfed here.\n");
          printf("TODO\n"); exit(1); // the file we want isn't encrypted.
        }
      }
      else if(passlen) {
        printf("\tPasslen is non-zero (%x) despite not being encrypted. Unarchiver would have barfed at offset (%i).\n", passlen, (ip - 1));
        exit(1); // This was wrong in my test file, but I fixed it and Unarchiver was still mad.
      }
    }

    // Now we can read the name.
    char* this_filename = (char*)malloc(filename_length + 1); // does stuffit not null-terminate?
    strncpy(this_filename, &bytes[ip], filename_length);
    this_filename[filename_length] = '\0';
    printf("filename = [%s]\n", this_filename);
    ip += filename_length;

    if(ip < header_end) {
      printf("Has comment..\n");
      unsigned int comment_length = GET2(bytes, ip);
      ip += 2;

      ip += 2; // skip 2 more bytes

      char* comment = (char*)malloc(comment_length + 1);
      strncpy(comment, &bytes[ip], comment_length);
      comment[comment_length] = '\0';
      printf("The comment is = [%s]\n", comment);
    }

    assert(ip == header_end);

    unsigned int something = GET2(bytes, ip);
    ip += 2;

    ip += 2; // skip 2 more bytes

    char* file_type = (char*)malloc(5);
    strncpy(file_type, &bytes[ip], 4);
    ip += 4;
    file_type[4] = '\0';
    printf("File type = [%s]\n", file_type);

    char* creator_code = (char*)malloc(5);
    strncpy(creator_code, &bytes[ip], 4);
    ip += 4;
    creator_code[4] = '\0';
    printf("Creator code = [%s]\n", creator_code);

    int finder_flags = GET2(bytes, ip);
    ip += 2;
    if(version == 1) {
      printf("v1: Skipping 22 bytes\n");
      ip += 22;
    } else {
      printf("Not v1: Skipping 18 bytes\n");
      ip += 18;
    }

    unsigned int resource_length = 0;
    unsigned int resource_crunched_length = 0;
    int resource_crc, resource_method;
    bool has_resource = something & 0x01;
    if(has_resource) {
      printf("Has resource!\n");
      resource_length = GET4(bytes, ip); ip += 4;
      resource_crunched_length = GET4(bytes, ip); ip += 4;
      resource_crc = GET2(bytes, ip); ip += 2;
      ip += 2; // skip 2 bytes
      resource_method = bytes[ip]; ip += 1;

      unsigned char passlen = bytes[ip]; ip += 1;

      if((file_flags & SIT5FLAGS_CRYPTED) && resource_length) {
        if(passlen != SIT5_KEY_LENGTH) {
          printf("passlen not right length. unarchiver would have barfed\n"); exit(1);
        }
        printf("TODO: get resource key\n"); exit(1);
      }
      else if(passlen) {
        printf("ip = %i passlen was specified (%x) but not encrypted?\n", (ip - 1), passlen);
        exit(1);
      }
    }

    unsigned int datastart = ip;
    if(file_flags & SIT5FLAGS_DIRECTORY) {
      // directories contain files, so get the files in it...
      ip = datastart;
      number_of_entries += number_of_files_in_dir;
    } else {
      // it's a "file."
      if(has_resource) {
        printf("Resource to extract\n");
        printf("\tMethod = %i (%s)\n", resource_method, get_name_of_method(resource_method));
        printf("\tLength = %i (%i compressed)\n", resource_length, resource_crunched_length);
        printf("\tCRC = %i\n", resource_crc);

        // add to extraction plan
        unsigned int resource_offset = datastart;
      }

      if(datafile_size || !has_resource) {
        printf("Data file to extract\n");
        printf("\tMethod = %i (%s)\n", datamethod, get_name_of_method(datamethod));
        printf("\tLength = %i (%i compressed)\n", datafile_size, crunched_size);
        printf("\tCRC = %i\n", stuffItCRC16);

        // add to extraction plan
        unsigned int data_offset = datastart + resource_crunched_length;

        // let's just dump this shit out to file, we'll deal with it later
        FILE* output = fopen(this_filename, "wb");
        fwrite(&bytes[data_offset], crunched_size, 1, output); // not efficient but who cares
        fclose(output);
        printf("... dumped.\n"); // 451709 should be the next offset maybe? oh it's just an icon file who cares
      }

      // Seek
      ip = datastart + resource_crunched_length + crunched_size;
    }
  }
}

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

  bytes = (char*)malloc((filelen + 1) * sizeof(char));
  fread(bytes, filelen, 1, fp);
  fclose(fp);

  const char *match="StuffIt (c)1997-\xFF\xFF\xFF\xFF Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/\x0d\x0a";

  for(unsigned int i = 0; i < strlen(match); ++i) { if(bytes[i] != match[i] &&
  match[i] != '\xFF') { printf("Wrong character at %i %i vs. %i\n", i, bytes[i],
  match[i]); printf("%s\n", match); for(int j = 0; j < i; ++j) { printf(" "); }
  printf("^\n"); return 1; } }

  printf("Header OK, continuing...\n");

  ip = 80; // skip ahead past header
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
  if(flags & SIT5FLAGS_CRYPTED) { printf("\tEncrypted?\n"); }

  // jump to the first offset
  ip = first_entry_offset;

  parseWithNumberOfTopLevelEntries(entries_in_root);
}
