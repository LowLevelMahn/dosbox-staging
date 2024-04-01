//#include "emu.hpp"
#include "regs.h"

#include "../helper.hpp"
#include "../regames.hpp"

#include <array>
#include <cassert>
#include <cstdint>

namespace {

uint8_t* s_game_image_begin = nullptr;

} // namespace

namespace swotl {

uint8_t* s_DOS_FILE_ACTIONS_ETC_sub_25C5A_begin{};

// first address after "debug hl.exe" as 32bit
const far_ptr_t dosbox_debugger_load_address16{0x1EF, 0};
const uint32_t dosbox_debugger_load_address32 = ptr16_to_offset32(
        dosbox_debugger_load_address16); 

far_ptr_t dosbox_break_point(uint32_t ida_ea_) {
	uint32_t offset32 = (ida_ea_ - IDA_BASE);
	uint32_t bp_offset32 = dosbox_debugger_load_address32 + offset32;
	return offset32_to_ptr16(bp_offset32);
}

void detect_exe(const std::string& program_name_, PhysPt loadaddress_)
{
	if (to_lower(program_name_) == "swotl.exe") {
		// gets set on every hl.exe start
		// loadseg = exe image start, right after_input PSP
		s_game_image_begin = MemBase + loadaddress_;

		std::array<uint8_t, 19> buffer{};
		memcpy(buffer.data(), s_game_image_begin + 3, buffer.size());

		//std::string x = hex_string(buffer.data(), buffer.size(), buffer.size());

		const std::array<uint8_t, buffer.size()> original{0x83,
		                                                  0xEC,
		                                                  0x0C,
		                                                  0xC6,
		                                                  0x06,
		                                                  0x4C,
		                                                  0x9C,
		                                                  0x00,
		                                                  0xC6,
		                                                  0x06,
		                                                  0x1F,
		                                                  0x9C,
		                                                  0x00,
		                                                  0xC6,
		                                                  0x06,
		                                                  0xC8,
		                                                  0xAD,
		                                                  0x00,
		                                                  0xC6};

		if (buffer != original) {
			LOG_MSG("!!!!!!!! SWOTL: not the correct swotl.exe");
		}

		LOG_MSG("!!!!!!!! SWOTL: swotl.exe startet");

		s_DOS_FILE_ACTIONS_ETC_sub_25C5A_begin =
		        by_IDA_EA_offset(s_game_image_begin, 0x25C5A);
	}
}

void detect_code_run(Bitu cs_, Bitu ip_)
{
	if (!s_game_image_begin) {
		return;
	}
}

bool detect_call_begin(Bitu cs_, Bitu ip_)
{
	if (!s_game_image_begin) {
		return false;
	}

	//printf("cs:ip => 0x%04X:0x%04X\n", cs_, ip_);

	const uint8_t* current = native_ptr(cs_, ip_);

	if (s_DOS_FILE_ACTIONS_ETC_sub_25C5A_begin == current) {
		/*
seg008:25A4 ; int __cdecl __far DOS_FILE_ACTIONS_ETC_sub_25BA4(char near *p_filename, __int16 p_unknown0, __int16 p_unknown1)
seg008:25A4 DOS_FILE_ACTIONS_ETC_sub_25BA4 proc far ; CODE XREF: sub_255B8+A4P
seg008:25A4
seg008:25A4 var_4           = byte ptr -4
seg008:25A4 var_3           = byte ptr -3
seg008:25A4 var_2           = byte ptr -2
seg008:25A4 var_1           = byte ptr -1
seg008:25A4 p_filename      = word ptr  6
seg008:25A4 p_arg_2         = word ptr  8
seg008:25A4 p_arg_4         = word ptr  0Ah
		*/		

		uint16_t bp = reg_sp - 2;
		
		auto filename_offset = stack_value<uint16_t>(bp + 0x06);
		char* filename_ptr = (char*)native_ptr(SegValue(ds), filename_offset);

		auto p_arg2 = stack_value<uint16_t>(bp + 0x08);
		auto p_arg4 = stack_value<uint16_t>(bp + 0x0A);

		// always???
		assert(p_arg2 == 0x8000);
		assert(p_arg4 == 0x01A4);

		printf("DOS_FILE_ACTIONS_ETC_sub_25C5A(p_filename=\"%s\",p_arg2=0x%04X,p_arg4=0x%04X)\n",
		       filename_ptr,
		       p_arg2,
		       p_arg4);
	}

	return false;
}

} // namespace historyline

#if REGAMES_GAME() == REGAMES_SWOTL

namespace regames {

void detect_exe(const std::string& program_name_, PhysPt loadaddress_)
{
	swotl::detect_exe(program_name_, loadaddress_);
}

void detect_code_run(Bitu cs_, Bitu ip_)
{
}

bool detect_call_begin(Bitu cs_, Bitu ip_)
{
	return swotl::detect_call_begin(cs_, ip_);
}

} // namespace regames

#endif

