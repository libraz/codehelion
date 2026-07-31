// This input is compiled only by the Windows artifact-fixture verifier.
// codehelion parses the resulting PE/PDB files but never loads the DLL.

extern "C" __declspec(dllexport) unsigned int duplicate_left(unsigned int value) {
  value = (value + 31U) ^ 0x9e3779b9U;
  value = (value << 5U) | (value >> 27U);
  value += 17U;
  return value ^ 0x7f4a7c15U;
}

extern "C" __declspec(dllexport) unsigned int duplicate_right(unsigned int value) {
  value = (value + 31U) ^ 0x9e3779b9U;
  value = (value << 5U) | (value >> 27U);
  value += 17U;
  return value ^ 0x7f4a7c15U;
}

#ifdef PE_PDB_MISMATCH
extern "C" __declspec(dllexport) unsigned int mismatch_marker(unsigned int value) {
  return value ^ 0x55aa55aaU;
}
#endif

extern "C" int __stdcall DllMain(void*, unsigned long, void*) {
  return 1;
}
