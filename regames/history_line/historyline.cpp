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

namespace historyline {

uint8_t* s_ILBM_USE1_sub_3AF32_begin{};
uint8_t* s_SOMETHING_WITH_FILENAME_OPEN_ETC_sub_1C56E_begin{};
uint8_t* s_ADD_FILE_EXTENSION_AND_MORE_sub_258E2_begin{};
uint8_t* s_SOMETHING_WITH_ALLOCATE_sub_3C9E4_begin{};
uint8_t* s_MAYBE_ILBM_STUFF_sub_3A4AC_begin{};
uint8_t* s_dseg_begin{};
uint8_t* s_ADLX_ADHRD_STUFF_sub_3FC2E_begin{};

// first address after "debug hl.exe" as 32bit
const far_ptr_t dosbox_debugger_load_address16{0x1EF, 0};
const uint32_t dosbox_debugger_load_address32 = ptr16_to_offset32(
        dosbox_debugger_load_address16); 

far_ptr_t dosbox_break_point(uint32_t ida_ea_) {
	uint32_t offset32 = (ida_ea_ - IDA_BASE);
	uint32_t bp_offset32 = dosbox_debugger_load_address32 + offset32;
	return offset32_to_ptr16(bp_offset32);
}

int get_breakpoints() {
	// seg017:024A B0 00 mov al, 0 -> parameter pushing before a
	// SOMETHING_WITH_FILENAME_OPEN_ETC_sub_1C56E call
	const far_ptr_t bp0 = dosbox_break_point(0x267DA);
	const far_ptr_t bp1 = dosbox_break_point(0x3A4AC);
	const far_ptr_t bp2 = dosbox_break_point(0x3FC2E); //ADLX_STUFF...
	const far_ptr_t bp3 = dosbox_break_point(0x3FBF5);
	int brk = 1;
	return 0;
}

static int x = get_breakpoints();

void detect_exe(const std::string& program_name_, PhysPt loadaddress_)
{
	if (to_lower(program_name_) == "hl.exe") {
		// gets set on every hl.exe start
		// loadseg = exe image start, right after_input PSP
		s_game_image_begin = MemBase + loadaddress_;

		std::array<uint8_t, 19> buffer{};
		memcpy(buffer.data(), s_game_image_begin + 3, buffer.size());

		// std::string x = hex_string(buffer.data(), buffer.size(),
		// buffer.size());

		const std::array<uint8_t, buffer.size()> original{0x2E,
		                                      0x89,
		                                      0x16,
		                                      0x84,
		                                      0x02,
		                                      0xB4,
		                                      0x30,
		                                      0xCD,
		                                      0x21,
		                                      0x8B,
		                                      0x2E,
		                                      0x02,
		                                      0x00,
		                                      0x8B,
		                                      0x1E,
		                                      0x2C,
		                                      0x00,
		                                      0x8E,
		                                      0xDA};

		if (buffer != original) {
			LOG_MSG("!!!!!!!! HISTORYLINE: not the correct hl.exe");
		}

		LOG_MSG("!!!!!!!! HISTORYLINE: hl.exe startet");

		s_ILBM_USE1_sub_3AF32_begin = by_IDA_EA_offset(s_game_image_begin,
		                                               0x3AF32);
		s_SOMETHING_WITH_FILENAME_OPEN_ETC_sub_1C56E_begin =
		        by_IDA_EA_offset(s_game_image_begin, 0x1C56E);
		s_ADD_FILE_EXTENSION_AND_MORE_sub_258E2_begin =
		        by_IDA_EA_offset(s_game_image_begin, 
		        0x258E2);
		s_SOMETHING_WITH_ALLOCATE_sub_3C9E4_begin =
		        by_IDA_EA_offset(s_game_image_begin, 0x3C9E4);
		s_MAYBE_ILBM_STUFF_sub_3A4AC_begin = by_IDA_EA_offset(s_game_image_begin,
		                                                      0x3A4AC);
		s_dseg_begin = by_IDA_EA_offset(s_game_image_begin, 0x4CD90);
		s_ADLX_ADHRD_STUFF_sub_3FC2E_begin = by_IDA_EA_offset(s_game_image_begin,
		                                                      0x3FC2E);
	}
}

void detect_code_run(Bitu cs_, Bitu ip_)
{
	if (!s_game_image_begin) {
		return;
	}

	const uint8_t* current = native_ptr(cs_, ip_);

	if (current == by_IDA_EA_offset(s_game_image_begin, 0x3A4BB)) {
		auto data = hexdump(native_ptr(SegValue(ds), reg_esi), 18, 18);
		printf("inside MAYBE_ILBM_STUFF_sub_3A4AC(data='%s')\n", data.c_str());
	}

	if (current == by_IDA_EA_offset(s_game_image_begin, 0x3A4C1)) {
		auto data = hexdump(native_ptr(SegValue(ds), reg_esi), 18, 18);
		printf("inside MAYBE_ILBM_STUFF_sub_3A4AC #2(data='%s')\n",
		       data.c_str());
	}
}

bool detect_call_begin(Bitu cs_, Bitu ip_)
{
	if (!s_game_image_begin) {
		return false;
	}

	//printf("cs:ip => 0x%04X:0x%04X\n", cs_, ip_);

	const uint8_t* current = native_ptr(cs_, ip_);

	if (s_ILBM_USE1_sub_3AF32_begin == current) {
		printf("ILBM_USE1_sub_3AF32\n%s\n",
		       hexdump(native_ptr(SegValue(es), reg_di), 1000, 16).c_str());
	}

	if ( s_ADD_FILE_EXTENSION_AND_MORE_sub_258E2_begin == current ) {

		printf("s_ADD_FILE_EXTENSION_AND_MORE_sub_258E2_begin: %X\n",
		       s_ADD_FILE_EXTENSION_AND_MORE_sub_258E2_begin);

#pragma pack(push,1)
		typedef char some_name[8];
		typedef char dir_name[6];
		typedef char extension_name[5];
		struct some_filename_stuff_t
		{
			some_name names[3];
			dir_name dirs[4];
			extension_name extensions[12];
		};
#pragma pack(pop)

		const some_filename_stuff_t* some_filename_stuff =
		        (some_filename_stuff_t*)by_IDA_EA_offset(s_game_image_begin,
		                                                 0x42EF3);

		/*
seg014:02C2                         arg_0           = word ptr  6
seg014:02C2                         arg_2           = word ptr  8
seg014:02C2                         filename_       = far_ptr_t ptr  0Ah
seg014:02C2                         extension_type_ = word ptr  0Eh 
		*/

		uint16_t bp        = reg_sp - 2;

		auto arg_0 = stack_value<uint16_t>(bp + 0x06);
		auto arg_2 = stack_value<uint16_t>(bp + 0x08);
		auto filename_     = stack_value<far_ptr_t>(bp + 0x0A);
		char* filename_ptr = (char*)native_ptr(filename_);
		auto extension_type_ = stack_value<uint16_t>(bp + 0x0E);

		printf("ADD_FILE_EXTENSION_AND_MORE_sub_258E2(arg_0=0x%04X, arg_2=0x%04X, filename=\"%s\", extension_type=0x%04X)\n", arg_0, arg_2, filename_ptr, extension_type_);

		constexpr uint16_t DO_NOT_ADD_EXTENSION = -1;

		printf("extension:\n");
		if (extension_type_ != DO_NOT_ADD_EXTENSION) // != don't add
		                                             // extension
		{
			printf(" %s\n",
			       some_filename_stuff->extensions[extension_type_]);
		}

		int brk = 1;
	}

	if (s_SOMETHING_WITH_FILENAME_OPEN_ETC_sub_1C56E_begin == current) {
		/*
		
int __cdecl __far SOMETHING_WITH_FILENAME_OPEN_ETC_sub_1C56E(char far *filename_, int p2_, int p3_, int p4_, int p5_, char *string_, __int8 p6_)

seg006:000E SOMETHING_WITH_FILENAME_OPEN_ETC_sub_1C56E proc far
seg006:000E                                         ;
seg006:000E seg006:000E var_1E          = dword ptr -1Eh
seg006:000E var_1A          = word ptr -1Ah
seg006:000E var_18          = word ptr -18h
seg006:000E var_16          = dword ptr -16h
seg006:000E var_12          = word ptr -12h
seg006:000E var_10          = word ptr -10h
seg006:000E var_D           = byte ptr -0Dh
seg006:000E var_C           = word ptr -0Ch
seg006:000E var_A           = word ptr -0Ah
seg006:000E var_8           = word ptr -8
seg006:000E var_6           = word ptr -6
seg006:000E buffer          = far_ptr_t ptr -4
------------------
seg006:000E filename_       = dword ptr  6
seg006:000E p2_             = word ptr  0Ah
seg006:000E p3_             = word ptr  0Ch
seg006:000E p4_             = word ptr  0Eh
seg006:000E p5_             = word ptr  10h
seg006:000E string_         = far_ptr_t ptr  12h
seg006:000E p6_             = byte ptr  16h
------------------
seg006:000E ...
		*/		

		uint16_t bp = reg_sp - 2;
		auto filename_ = stack_value<far_ptr_t>(bp + 0x06);
		char* filename_ptr = (char*)native_ptr(filename_);

		//-----
		// p2+p3 could be also be a far pointer -> maybe to the uncompressed result?
		auto p2_ = stack_value<uint16_t>(bp + 0x0A);
		auto p3_ = stack_value<uint16_t>(bp + 0x0C);
		auto some_buffer = stack_value<far_ptr_t>(bp + 0x0A); // p3_:p2_
		// some_buffer seems to contain the unpacked data after uncompression
		//-----

		auto file_read_buffer = stack_value<far_ptr_t>(bp + 0x0E);
		auto unknown_buffer_ = stack_value<far_ptr_t>(bp + 0x12);
		char* unknown_buffer_ptr = (char*)native_ptr(unknown_buffer_);
		auto p6_ = stack_value<uint8_t>(bp + 0x16);

		printf("SOMETHING_WITH_FILENAME_OPEN_ETC_sub_1C56E(\"%s\",some_buffer(0x%04X:0x%04X) => 0x%08X),file_read_buffer(0x%04X:0x%04X => 0x%08X),unknown_buffer(0x%04X:0x%04X => 0x%08X),0x%02X)\n",
		       filename_ptr,
		       some_buffer.segment,
		       some_buffer.offset,
		       ptr16_to_offset32(some_buffer),
		       file_read_buffer.segment,
		       file_read_buffer.offset,
		       ptr16_to_offset32(file_read_buffer),
		       unknown_buffer_.segment,
			   unknown_buffer_.offset,
		       ptr16_to_offset32(unknown_buffer_),
		       p6_);

		static int counter = 0;
		auto cs_val        = SegValue(cs);
		printf("cs:ip => %04X:%04X, %i\n", cs_val, reg_eip, ++counter);

		if (std::string(filename_ptr) == "LIB\\unit.LIB") {
			//bool wait = true;
			int brk = 1;
		}

	}

	if (s_SOMETHING_WITH_ALLOCATE_sub_3C9E4_begin == current) {
	/*
	seg107:0004 ; unsigned __int32 __cdecl __far
	SOMETHING_WITH_ALLOCATE_sub_3C9E4(unsigned __int32 byte_count_)
		byte_count_     = dword ptr  6
	*/

		uint16_t bp        = reg_sp - 2;
		auto byte_count_     = stack_value<uint32_t>(bp + 0x06);

				printf("SOMETHING_WITH_ALLOCATE_sub_3C9E4_begin(byte_count_= %u)\n",
		       byte_count_);
	}

	if (s_MAYBE_ILBM_STUFF_sub_3A4AC_begin == current) {
		uint16_t bp = reg_sp - 2;
		
		uint16_t si_value = stack_value<uint16_t>(bp + 0x0A);
		auto data = hex_string(s_dseg_begin + si_value, 18);

		printf("MAYBE_ILBM_STUFF_sub_3A4ACn(data='%s')\n", data.c_str());
	}

	if (s_ADLX_ADHRD_STUFF_sub_3FC2E_begin == current) {
		uint16_t bp = reg_sp - 2;
		/*
seg122:0A9E p0_             = word ptr  6
seg122:0A9E p1_buffer_      = far_ptr_t ptr  8
seg122:0A9E p2_             = word ptr  0Ch
		*/
		uint16_t p0_ = stack_value<uint16_t>(bp + 0x06);
		auto p1_buffer_ = stack_value<far_ptr_t>(bp + 0x08);
		char* p1_buffer_ptr = (char*)native_ptr(p1_buffer_);
		uint16_t p2_ = stack_value<uint16_t>(bp + 0x0C);

		printf("ADLX_ADHRD_STUFF_sub_3FC2E(p0_=0x%04X, p2_=0x%04X)\n", p0_, p2_);
		printf("%s\n", hex_string(p1_buffer_ptr, 64).c_str());
	}

	return false;
}

} // namespace historyline

#if REGAMES_GAME() == REGAMES_HISTORY_LINE

namespace regames {

void detect_exe(const std::string& program_name_, PhysPt loadaddress_)
{
	historyline::detect_exe(program_name_, loadaddress_);
}

void detect_code_run(Bitu cs_, Bitu ip_)
{
	historyline::detect_code_run(cs_, ip_);
}
bool detect_call_begin(Bitu cs_, Bitu ip_)
{
	return historyline::detect_call_begin(cs_, ip_);
}

} // namespace regames

#endif

