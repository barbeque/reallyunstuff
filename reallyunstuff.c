#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char* argv[]) {
  FILE* fp = fopen("/Users/mike/Downloads/DoveEthernetkaart (1).sit", "rb");
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

  for(unsigned int i = 0; i < strlen(match); ++i) {
    if(bytes[i] != match[i] && match[i] != '\xFF') {
      printf("Wrong character at %i %i vs. %i\n", i, bytes[i], match[i]);
      printf("%s\n", match);
      for(int j = 0; j < i; ++j) {
        printf(" ");
      }
      printf("^\n");
      return 1;
    }
  }

  printf("Header OK, continuing...\n");
}
