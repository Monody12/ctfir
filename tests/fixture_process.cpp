// Inert process fixture: sleeps only; no shell/network/file writes. Linux containers only.
#include <unistd.h>
int main() { sleep(60); return 0; }
