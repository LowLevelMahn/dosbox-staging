#pragma once

#include "mem.h"

#include <string>

#define REGAMES_PRINT_EXE_LOAD_ADDRESS() (true)
#define REGAMES_LOG_DOS_FILE_STUFF()     (true)

namespace regames {

#define REGAMES() (true)

// game
#define REGAMES_INACTIVE     0
#define REGAMES_ALPHA_WAVES  1
#define REGAMES_STUNTS       2
#define REGAMES_HISTORY_LINE 3
#define REGAMES_SWOTL        4

#define REGAMES_GAME() (REGAMES_ALPHA_WAVES)

void detect_exe(const std::string& program_name_, PhysPt loadaddress_);
void detect_code_run(Bitu cs_, Bitu ip_);
bool detect_call_begin(Bitu cs_, Bitu ip_);

#if REGAMES_GAME() == REGAMES_INACTIVE

inline void detect_exe(const std::string& program_name_, PhysPt loadaddress_) {}
inline void detect_code_run(Bitu cs_, Bitu ip_) {}
inline bool detect_call_begin(Bitu cs_, Bitu ip_)
{
	return false;
}

#endif

} // namespace regames
