#include "../helper.hpp"
#include "../regames.hpp"

#include "../emu.hpp"
#include "regs.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <fstream>
#include <functional>
#include <stack>

namespace {

uint8_t* s_game_image_begin = nullptr;

} // namespace

namespace alpha_waves {

#define COMPRESSION_STUFF() (false)

#if COMPRESSION_STUFF()
uint8_t* s_compress_proc_begin{};
uint8_t* s_cc1_read_begin{};
#endif

uint8_t* s_sub_1D5D1_begin{};
uint8_t* s_sub_15F18_begin{};

void detect_exe(const std::string& program_name_, PhysPt loadaddress_)
{
	if (to_lower(program_name_) == "vga.exe") {
		// gets set on every game.exe start
		// loadseg = exe image start, right after_input PSP
		s_game_image_begin = MemBase + loadaddress_;

		std::array<uint8_t, 9> buffer{};
		memcpy(buffer.data(), s_game_image_begin + 3, buffer.size());

		// std::string x = hex_string(buffer.data(), buffer.size(),
		// buffer.size());

		const std::array<uint8_t, 9> original{
		        0x2E, 0x89, 0x16, 0xBA, 0x01, 0xB4, 0x30, 0xCD, 0x21};

		if (buffer != original) {
			LOG_MSG("!!!!!!!! ALPHA WAVES: not the correct vga.exe");
		}

		LOG_MSG("!!!!!!!! ALPHA WAVES: vga.exe startet");

#if COMPRESSION_STUFF()
		// get pointer of UNCOMPRESS_sub_1BAE7 ==> seg000(cs):BAE7
		s_compress_proc_begin = by_IDA_EA_offset(s_game_image_begin, 0x1BAE7);
		s_cc1_read_begin = by_IDA_EA_offset(s_game_image_begin, 0x1B172);
#endif
		s_sub_1D5D1_begin = by_IDA_EA_offset(s_game_image_begin, 0x1D5D1);

		std::array<uint8_t, 14> buffer2{};
		memcpy(buffer2.data(), s_sub_1D5D1_begin, buffer2.size());
		std::string x2 = hex_string(buffer2.data(), buffer2.size());
		int brk        = 1;

		s_sub_15F18_begin = by_IDA_EA_offset(s_game_image_begin, 0x15F18);
	}
}

namespace {
int state = 0;
// 0 = init // first_instruction
// 1 = first call of UNCOMPRESS_sub_1BAE7 - waiting for last_instruction, can
// happen in loop

int block = 0;
} // namespace

void detect_code_run(Bitu cs_, Bitu ip_)
{
	if (!s_game_image_begin) {
		return;
	}

	const uint8_t* current = MemBase + PhysicalMake(cs_, ip_);

#if COMPRESSION_STUFF()
	/*
	first: IDA-EA: 0x1BAE7

	seg000:BAE7 06                                      push    es
	seg000:BAE8 57                                      push    di
	seg000:BAE9 B9 80 00                                mov     cx, 80h ;
	'Ç' seg000:BAEC 8C D8                                   mov     ax, ds
	seg000:BAEE 8E C0                                   mov     es, ax
	*/

	static const std::string path = "d:/temp/alpha";

	auto block_info = []() { return "block_ " + std::to_string(block); };

	const uint8_t* first_instruction = by_IDA_EA_offset(s_game_image_begin,
	                                                    0x1BAE7);
	if (current == first_instruction) {
		std::array<uint8_t, 9> buffer{};
		memcpy(buffer.data(), current, buffer.size());
		const std::array<uint8_t, 9> original{
		        0x06, 0x57, 0xB9, 0x80, 0x00, 0x8C, 0xD8, 0x8E, 0xC0};

		assert(buffer == original);

		if (state == 0) {
			state = 1;

			// store registers (DS:SI, ES:DI, CS => block_n_regs.txt)
			char buffer[1024]{};
			sprintf_s(buffer,
			          "DS=0x%04X, SI=0x%04X, ES=0x%04X, DI=0x%04X, CS = 0x%04X\n",
			          SegValue(ds),
			          reg_si,
			          SegValue(es),
			          reg_di,
			          SegValue(cs));
			write_string_file(path + "/" + block_info() + "_regs_before.txt",
			                  buffer);

			// store 1MB memory (block_n_dump_before.bin)
			write_binary_file(path + "/" + block_info() + "_dump_before.bin",
			                  MemBase,
			                  1024 * 1024);

			printf("begin: UNCOMPRESS_sub_1BAE7\n");
		}
	}

	/*
	last: IDA-EA: 0x1BBE0
	seg000:BBE0                         locret_1BBE0: ; CODE XREF:
	UNCOMPRESS_sub_1BAE7+F4j seg000:BBE0 C3 retn seg000:BBE1 ;
	---------------------------------------------------------------------------
	seg000:BBE1
	seg000:BBE1                         loc_1BBE1: ; CODE XREF:
	UNCOMPRESS_sub_1BAE7+ECj seg000:BBE1 1E push    ds seg000:BBE2 2E 8B 36
	A6 BA                          mov     si, word ptr cs:dword_1BAA4+2
	*/

	const uint8_t* last_instruction = by_IDA_EA_offset(s_game_image_begin,
	                                                   0x1BBE0);
	if (current == last_instruction) {
		std::array<uint8_t, 7> buffer{};
		memcpy(buffer.data(), current, buffer.size());
		const std::array<uint8_t, 7> original{
		        0xC3, 0x1E, 0x2E, 0x8B, 0x36, 0xA6, 0xBA};

		assert(buffer == original);

		if (state == 1) {
			printf("end: UNCOMPRESS_sub_1BAE7\n");

			// store 1MB result memory )
			write_binary_file(path + "/" + block_info() + "_dump_after.bin",
			                  MemBase,
			                  1024 * 1024);

			state = 0;
			++block;
		}
	}
#endif
}

/*
hook this function an print parameter cc1_file and block_nr

seg000:B172                         ; int __cdecl READ_CC1_BLOCK_sub_1B172(char
*cc1_file, int block_nr) seg000:B172 READ_CC1_BLOCK_sub_1B172 proc near      ;
CODE XREF: sub_1789B+26p seg000:B172 ; sub_18E2C+Fp ... seg000:B172
seg000:B172 dest            = byte ptr -542h seg000:B172 var_52E = dword ptr
-52Eh seg000:B172                         var_528         = word ptr -528h
seg000:B172                         var_526         = word ptr -526h seg000:B172
var_524         = word ptr -524h seg000:B172                         var_522 =
word ptr -522h seg000:B172                         var_520         = word ptr
-520h seg000:B172                         var_51E         = word ptr -51Eh
seg000:B172                         var_51C         = word ptr -51Ch
seg000:B172                         var_51A         = word ptr -51Ah
seg000:B172                         var_518         = word ptr -518h
seg000:B172                         var_516         = word ptr -516h
seg000:B172                         var_514         = word ptr -514h
seg000:B172                         var_512         = word ptr -512h
seg000:B172                         var_510         = byte ptr -510h
seg000:B172                         str             = dword ptr  4
seg000:B172                         maybe_block_nr  = word ptr  8
*/

// replace call at
// seg000:BADC E8 08 00                                call UNCOMPRESS_sub_1BAE7
// to
// native code

void UNCOMPRESS_sub_1BAE7_cleanup(emu_t& e);
void UNCOMPRESS_sub_1BAE7(emu_t& e);

bool detect_call_begin(Bitu cs_, Bitu ip_)
{
	const uint8_t* current = MemBase + PhysicalMake(cs_, ip_);

#if COMPRESSION_STUFF()
	if (!s_compress_proc_begin) {
		return false;
	}

	if (s_cc1_read_begin == current) {
		uint16_t bp = reg_sp - 2;

		far_ptr_t str_ptr       = stack_value<far_ptr_t>(bp + 4);
		char* str               = (char*)native_ptr(str_ptr);
		uint16_t maybe_block_nr = stack_value<uint16_t>(bp + 8);
		printf("READ_CC1_BLOCK_sub_1B172(cc1_file=\"%s\", block_nr=%i)\n",
		       str,
		       maybe_block_nr);
	} else if (s_compress_proc_begin == current) {
		return false; // let the game uncompress itself

		printf("compression called\n");

		emu_t e;
		// copy memory
		::memcpy(e.memory().data(), MemBase, 1 * 1024 * 1024);

		e.cs = SegValue(cs);
		e.ds = SegValue(ds);
		e.es = SegValue(es);
		e.si = reg_si;
		e.di = reg_di;

#if 1
		UNCOMPRESS_sub_1BAE7_cleanup(e);
#else
		UNCOMPRESS_sub_1BAE7(e);
#endif

		::memcpy(MemBase, e.memory().data(), 1 * 1024 * 1024);

		return true;
	}
#endif

	if (current == s_sub_1D5D1_begin) {
		uint16_t bp = reg_sp - 2;

		/*
		                arg_0   = word ptr  4
		                arg_2   = word ptr  6
		                arg_4   = word ptr  8
		                arg_6   = word ptr  0Ah
		                arg_8   = word ptr  0Ch
		*/

		uint16_t arg_0 = stack_value<uint16_t>(bp + 4);
		uint16_t arg_2 = stack_value<uint16_t>(bp + 6);
		uint16_t arg_4 = stack_value<uint16_t>(bp + 8);
		uint16_t arg_6 = stack_value<uint16_t>(bp + 0xA);
		uint16_t arg_8 = stack_value<uint16_t>(bp + 0xC);

		printf("sub_1D5D1(arg_0=0x%04X, arg_2=0x%04X, arg_4=0x%04X, arg_6=0x%04X, arg_8=0x%04X)\n",
		       arg_0,
		       arg_2,
		       arg_4,
		       arg_6,
		       arg_8);
	}

	if (current == s_sub_15F18_begin) {
		uint16_t bp   = reg_sp - 2;
		uint8_t arg_0 = stack_value<uint8_t>(bp + 4);

		printf("sub_15F18(arg_0=0x%04X)\n", arg_0);
	}

	return false;
}

// seg000:B172                         ; int __cdecl
// READ_CC1_BLOCK_sub_1B172(char *s, int maybe_block_nr) seg000:B172
// READ_CC1_BLOCK_sub_1B172 proc near      ; CODE XREF: sub_1789B+26p
// seg000:B172 ; sub_18E2C+Fp ...

// seg000:B185 FF 76 06                                push    word ptr [bp+s+2]
// seg000:B188 FF 76 04                                push    word ptr [bp+s] ;
// src

// s is far_ptr

// seg000:B214 8B 5E 08                                mov     bx,
// [bp+maybe_block_nr]

// block_nr is word

/*
        uint16_t bp = reg_sp - 2;
        far_ptr_t string = stack_value<far_ptr_t>(bp + 4);
        uint16_t bock_nr = stack_value<uint16_t>(bp + 8);
*/

// make offset as small as possible
void normalize_ptr(uint16_t& seg_, uint16_t& ofs_)
{
	seg_ += ofs_ / 16;
	ofs_ = ofs_ % 16;
}

constexpr uint8_t LAST_BLOCK     = 0;
constexpr uint8_t NOT_LAST_BLOCK = 1;

#pragma pack(push, 1)
struct block_t {
	uint8_t packed_size{}; // 0xBA9A
	uint8_t flag{}; // 0 = last block, 1 = more blocks comming -> 0xBA9B
	uint16_t data_len{}; // (un)compressed data -> 0xBA9C
};
static_assert(sizeof(block_t) == 4, "invalid size");
#pragma pack(pop)

struct stack_item_t {
	uint8_t a{};
	uint8_t b{};
};

void DEBUG_prepare_result_ptrs(const uint8_t* input_ptr, emu_t::ptr16_t& input_ptr16,
                               emu_t& e, uint8_t* output_ptr)
{
	// DEBUG/TEST: getting "processed" input/output size
	// from outside this routine

	// set es:di to point to output end (as original code
	// behave)
	const auto es_di = e.ptr_to_ptr16(output_ptr);
	e.es             = es_di.segment;
	e.di             = es_di.offset;
	input_ptr16      = e.ptr_to_ptr16(input_ptr); // overwrite
	                                              // far ptr with
	                                              // new position
}

#define PRINT_STACK() (false)

struct tables_t {
	// uint8_t *byte_000{};
	std::vector<uint8_t> table0;

	// uint8_t *byte_100{};
	std::vector<uint8_t> table1;

	// uint8_t *byte_301{};
	std::vector<uint8_t> table3;

	// uint8_t *byte_402{};
	std::vector<uint8_t> table4;
};

constexpr uint8_t UNPACKED_VAL = 0;

void UNCOMPRESS_sub_1BAE7_cleanup_uncompress_part(const uint8_t start_val_,
                                                  const uint8_t*& input_ptr,
                                                  uint8_t*& output_ptr,
                                                  const tables_t& tables)
{
	std::stack<stack_item_t> stack;

	uint8_t var2 = start_val_;
	assert(var2 > 0);

outer_loop:
	// var1 is not available here, later defined
	// printf("restart_loop var2: % 2u\n", var2);

	stack.push({tables.table1[var2], var2});
#if PRINT_STACK()
	printf("%spush a: % 2u b: % 2u\n",
	       std::string(stack.size() * 2, ' ').c_str(),
	       stack.top().a,
	       stack.top().b);
#endif

	uint8_t var1 = tables.table0[var2];
	assert(var1 >= 0);

#define MORE_INLINE() (true)

	while (true) { // loop1
		const uint8_t table3_val = tables.table3[var1];
		assert(table3_val >= 0);

		if (table3_val == UNPACKED_VAL) {
			*output_ptr++ = var1;
#if MORE_INLINE()
			if (stack.size() == 0) {
				return;
			}

			const stack_item_t& item = stack.top();
			// from stack
			var1 = item.a;
			var2 = item.b;
			stack.pop();

#else
			goto end_or_loop; // overwrites var1 and var2 or ends -
			                  // continues loop1
#endif
		} else if (var2 > table3_val) {
			var2 = table3_val;
			goto outer_loop; // only var2 is relevant here
		} else {
			const uint8_t old_var1 = var1;
			const uint8_t old_var2 = var2;
			var2                   = table3_val;
			while (true) { // loop2
				assert(var2 > 0);
				var2 = tables.table4[var2];
				if (var2 == UNPACKED_VAL) {
					*output_ptr++ = old_var1;
#if MORE_INLINE()
					if (stack.size() == 0) {
						return;
					}

					const stack_item_t item = stack.top();
					stack.pop();

					// from stack
					var1 = item.a;
					var2 = item.b;

					break;
#else
					goto end_or_loop; // leaves loop2,
					                  // overwrites var1 and
					                  // var2 or ends
#endif
				} else if (var2 < old_var2) {
					goto outer_loop; // only var2 is
					                 // relevant here
				} else {
					// get next value from table4
				}
			}
		}
		// ---------------------------------------------------------------------------

#if !MORE_INLINE()
		assert(false);

	end_or_loop: // only reachable by gotos
		if (stack.size() == 0) {
			return;
		}

		const stack_item_t item = stack.top();
#if PRINT_STACK()
		printf("%spop  a: % 2u b: % 2u\n",
		       std::string(stack.size() * 2, ' ').c_str(),
		       stack.top().a,
		       stack.top().b);
#endif
		stack.pop();

		// from stack
		var1 = item.a;
		var2 = item.b;
#endif
	}
}

tables_t prepare_tables(emu_t& e, const block_t& block, const uint8_t*& input_ptr)
{
	assert(block.packed_size != 0);

	//----------
	// only for uncompressing
	// uint8_t *byte_000 = e.byte_ptr(e.ds, 0x000);
	// uint8_t *byte_001 = e.byte_ptr(e.ds, 0x001);
	// uint8_t *byte_100 = e.byte_ptr(e.ds, 0x100);
	// uint8_t *byte_101 = e.byte_ptr(e.ds, 0x101);
	// uint8_t *byte_200 = e.byte_ptr(e.ds, 0x200);
	// uint8_t *table2 = e.byte_ptr(e.ds, 0x201);
	// uint8_t *byte_301 = e.byte_ptr(e.ds, 0x301);
	// uint8_t *byte_402 = e.byte_ptr(e.ds, 0x402);
	//----------

	// read & prepare uncompress-helper tables
	std::vector<uint8_t> table0(1 + block.packed_size);
	std::vector<uint8_t> table1(1 + block.packed_size);
	std::vector<uint8_t> table2(block.packed_size); // only needed for
	                                                // initialization, not
	                                                // for uncompression
	std::vector<uint8_t> table3(256);
	std::vector<uint8_t> table4(1 + block.packed_size);
	{
		::memcpy(table2.data(), input_ptr, block.packed_size);
		input_ptr += block.packed_size;

		table0[0] = 0xFF; // unused, never read
		::memcpy(&table0[1], input_ptr, block.packed_size);
		input_ptr += block.packed_size;

		table1[0] = 0xFF; // unused, never read
		::memcpy(&table1[1], input_ptr, block.packed_size);
		input_ptr += block.packed_size;

		// its currently, unclear what the max-packed_size could be
		// packed_size is uint8_t so max would be 255

		for (int i = 0; i < block.packed_size; ++i) {
			const uint8_t ofs   = table2[i];
			const uint8_t index = i + 1; // (0..255)+1
			assert(ofs >= 0);
			uint8_t* value = &table3[ofs]; // [0] is used
			table4[index]  = *value; // 1+256  [0] ignored, [1-256]
			*value         = index;
		}
		table4[0] = 0xFF; // unused, never read
	}

	const tables_t tables{table0, table1, table3, table4};

	return tables;
}

void UNCOMPRESS_sub_1BAE7_cleanup_uncompress_block(const block_t& block,
                                                   const uint8_t*& input_ptr,
                                                   uint8_t*& output_ptr, emu_t& e)
{
	const tables_t tables = prepare_tables(e, block, input_ptr);

	for (int i = 0; i < block.data_len; ++i) {
		const uint8_t var1 = *input_ptr++;
		const uint8_t var2 = tables.table3[var1]; // var1 0..n

		if (var2 == UNPACKED_VAL) {   // uncompressed part
			*output_ptr++ = var1; // just store value
		} else {                      // compressed part
			UNCOMPRESS_sub_1BAE7_cleanup_uncompress_part(var2,
			                                             input_ptr,
			                                             output_ptr,
			                                             tables);
		}
	}
}

void UNCOMPRESS_sub_1BAE7_cleanup(emu_t& e)
{
	// uint16_t *word_BAA2 = e.word_ptr(e.cs, 0xBAA2);

	emu_t::ptr16_t& input_ptr16 = *e.memory<emu_t::ptr16_t>(e.cs, 0xBAA4);
	const uint8_t* input_ptr    = e.byte_ptr(input_ptr16);

	uint8_t* output_ptr = e.byte_ptr(e.es, e.di);

	while (true) {
		block_t block{};
		::memcpy(&block, input_ptr, sizeof(block));
		input_ptr += sizeof(block);
		assert(block.flag == LAST_BLOCK || block.flag == NOT_LAST_BLOCK);

		if (block.packed_size == 0) { // is not packed?
			::memcpy(output_ptr, input_ptr, block.data_len);
			input_ptr += block.data_len;
			output_ptr += block.data_len;
		} else {
			// biggest block.packed_size so far: 223
			UNCOMPRESS_sub_1BAE7_cleanup_uncompress_block(block,
			                                              input_ptr,
			                                              output_ptr,
			                                              e);
		}

		if (block.flag == LAST_BLOCK) {
			DEBUG_prepare_result_ptrs(input_ptr, input_ptr16, e, output_ptr);

			return; // the-end
		}
	}
}

struct data_block_t {
	uint32_t packed_size{};
	uint32_t unpacked_size{};
	std::vector<uint8_t> data;
};

inline uint8_t lo(uint16_t value_)
{
	return value_ & 0xFF;
}

inline uint8_t hi(uint16_t value_)
{
	return value_ >> 8;
}

inline uint16_t lo(uint32_t value_)
{
	return value_ & 0xFFFF;
}

inline uint16_t hi(uint32_t value_)
{
	return value_ >> 16;
}

inline uint16_t swap(const uint16_t value_)
{
	return (value_ << 8) + (value_ >> 8);
}

inline uint32_t swap(const uint32_t value_)
{
	const uint16_t lv = lo(value_);
	const uint16_t hv = hi(value_);
	return (swap(lv) << 16) + swap(hv);
}

std::vector<uint8_t> read_binary_file(const std::string& filename_)
{
	std::ifstream file(filename_, std::ios::binary);
	assert(file);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)),
	                            std::istreambuf_iterator<char>());
}

std::vector<data_block_t> read_cc1_file(const std::string& filepath_)
{
	const std::vector<uint8_t> content = read_binary_file(filepath_);

	const uint8_t* current = content.data();

	uint16_t offset_count = swap(*(uint16_t*)current);
	current += sizeof(uint16_t);

	std::vector<uint32_t> offset_table(offset_count);
	for (size_t i = 0; i < offset_count; ++i) {
		uint32_t offset = swap(*(uint32_t*)current);
		current += sizeof(uint32_t);
		offset_table[i] = offset;
	}

	std::vector<data_block_t> data_blocks(offset_count);

	for (size_t i = 0; i < offset_count; ++i) {
		uint32_t packed_size = swap(*(uint32_t*)current);
		current += sizeof(uint32_t);

		uint32_t unpacked_size = swap(*(uint32_t*)current);
		current += sizeof(uint32_t);

		std::vector<uint8_t> data(packed_size);
		::memcpy(data.data(), current, packed_size);
		current += packed_size;

		data_blocks[i] = {packed_size, unpacked_size, data};
	}

	// size of the parts + offsets fits exact the file size? no gaps?
	size_t result_size = sizeof(uint16_t) + offset_count * sizeof(uint32_t);
	for (size_t i = 0; i < offset_count; ++i) {
		result_size += sizeof(uint32_t) + sizeof(uint32_t) +
		               data_blocks[i].packed_size;
	}
	assert(result_size == content.size());

	return data_blocks;
}

std::vector<uint8_t> run_test(std::function<void(emu_t& e)> test_func_,
                              const data_block_t& db, size_t* used_input_bytes,
                              size_t* used_output_bytes)
{
	// memory
	emu_t e;

	e.cs = 0;
	e.ds = 0x1000;
	e.si = 0;

	// output
	e.es = 0xE000;
	e.di = 0;

	uint8_t* output_data = e.byte_ptr(e.es, e.di);
	::memset(output_data, 0, db.unpacked_size);

	uint16_t* word_BAA2 = e.word_ptr(e.cs, 0xBAA2);
	*word_BAA2          = 0;

	// input
	far_ptr_t* ptr_BAA4 = e.memory<far_ptr_t>(e.cs, 0xBAA4);
	ptr_BAA4->segment   = 0xC000;
	ptr_BAA4->offset    = 0;

	const auto before_input  = *ptr_BAA4;
	const auto before_output = e.offset32(e.es, e.di);

	uint8_t* input_data = e.byte_ptr(ptr_BAA4->segment, ptr_BAA4->offset);
	::memcpy(input_data, db.data.data(), db.data.size());

	test_func_(e);

	const auto after_input  = *ptr_BAA4;
	const auto after_output = e.offset32(e.es, e.di);

	*used_input_bytes = e.offset32(after_input.segment, after_input.offset) -
	                    e.offset32(before_input.segment, before_input.offset);

	*used_output_bytes = after_output - before_output;

	return {output_data, output_data + db.unpacked_size};
}

// uncompress_cc1.cpp
// uncompress_cc1 [CC1-FILE]
//   -> CC1-FILE.block0000.bin

void cc1_read_test()
{
#if 1
	const std::string game_root = R"(F:\projects\fun\dos_games_rev\alpha_waves_dev\tests\alpha)";

	const std::vector<std::string> files{"PROGS.CC1",
	                                     "GRAPHS.CC1",
	                                     "MUSIC_A.CC1",
	                                     "MUSIC_B.CC1",
	                                     "MUSIC_T.CC1",
	                                     "TEXTES.CC1"};
#else
	const std::string game_root = R"(F:\projects\fun\dos_games_rev\alpha_waves_dev\tests\000135_alone_in_the_dark)";

	const std::vector<std::string> files{"disk4\\INDARK.CC1", "disk1\\INFO.CC1"};
#endif

	for (const auto& file : files) {
		const std::string in_filepath  = game_root + "\\" + file;
		const std::string out_filepath = game_root +
		                                 "\\cc1_extract\\ported\\" + file;
		printf("%s\n", in_filepath.c_str());
		std::vector<data_block_t> data_blocks = read_cc1_file(in_filepath);

#if 1
		// print info
		printf("blocks\n");
		for (size_t i = 0; i < data_blocks.size(); ++i) {
			const auto& db = data_blocks[i];
			printf("  [%u] packed_size: %u, unpacked_size: %u\n",
			       i,
			       db.packed_size,
			       db.unpacked_size);

			const uint16_t word_BAA2 = 0;

			const uint8_t* input = db.data.data();
			std::vector<uint8_t> unpacked(db.unpacked_size);
			uint8_t* output = unpacked.data();

			size_t used_input_bytes  = 0;
			size_t used_output_bytes = 0;

			{
				size_t used_input_bytes1  = 0;
				size_t used_output_bytes1 = 0;
				auto unpacked1 = run_test(UNCOMPRESS_sub_1BAE7,
				                          db,
				                          &used_input_bytes1,
				                          &used_output_bytes1);

				size_t used_input_bytes2  = 0;
				size_t used_output_bytes2 = 0;
				auto unpacked2 = run_test(UNCOMPRESS_sub_1BAE7_cleanup,
				                          db,
				                          &used_input_bytes2,
				                          &used_output_bytes2);

				assert(used_input_bytes1 == used_input_bytes2);
				assert(used_output_bytes1 == used_output_bytes2);
				assert(unpacked1 == unpacked2);

#if 1
				char filename[256]{};
				sprintf(filename,
				        "%s_block%05u.bin",
				        out_filepath.c_str(),
				        i);
				write_binary_file(filename,
				                  unpacked2.data(),
				                  unpacked2.size());
#endif
			}

			// PROGS.CC1
			/*
			sound.pc_buz
			sound.tandy
			sound.adlib
			gfx.cga_hercules
			gfx.ega_vga
			gfx.tandy
			*/
			// if (used_input_bytes != db.data.size()) {
			//	printf("    ===> used_input_bytes[[%u]] !=
			// db.data.size()[[%u]]\n", used_input_bytes,
			// db.data.size());
			//}
			// if (used_output_bytes != unpacked.size()) {
			//	printf("    ===> used_output_bytes[[%u]] !=
			// unpacked.size()[[%u]]\n",
			// used_output_bytes,unpacked.size() );
			//}

#if 0
            char filename[256]{};
            sprintf( filename, "%s_block%05u.bin", out_filepath.c_str(), i );
            write_binary_file( filename, unpacked.data(), unpacked.size() );
#endif
		}
#endif
	}

	int brk = 1;
}

struct static_test_t {
	static_test_t()
	{
		// cc1_read_test();
	}
};

static_test_t test;

void UNCOMPRESS_sub_1BAE7(emu_t& e)
{
start:
	e.push(e.es);
	e.push(e.di);
	e.cx = 0x80;
	e.ax = e.ds;
	e.es = e.ax;
	e.di = 0x301;
	e.xor16(e.ax, e.ax);
	e.rep_stosw();
	e.pop(e.di);
	e.pop(e.es);
	e.sub(e.di, *e.word_ptr(e.cs, 0xBAA2));
	e.ax = e.di;
	e.shr(e.ax, 1);
	e.shr(e.ax, 1);
	e.shr(e.ax, 1);
	e.shr(e.ax, 1);
	e.cx = e.es;
	e.add(e.cx, e.ax);
	e.es = e.cx;
	e.and16(e.di, 0x0F);
	e.add(e.di, *e.word_ptr(e.cs, 0xBAA2));
	e.push(e.ds);
	e.push(e.es);
	e.push(e.si);
	e.push(e.di);
	e.cx = 4;
	e.di = 0xBA9A; // offset byte_1BA9A; ???
	e.ax = e.cs;   // seg seg000 // cs register; ???
	e.es = e.ax;
	e.lds(e.si, *e.dword_ptr(e.cs, 0xBAA4));
	e.ax = e.si;
	e.shr(e.ax, 1);
	e.shr(e.ax, 1);
	e.shr(e.ax, 1);
	e.shr(e.ax, 1);
	e.dx = e.ds;
	e.add(e.ax, e.dx);
	e.ds = e.ax;
	e.and16(e.si, 0x0F);
	*e.word_ptr(e.cs, 0xBAA4)     = e.si;
	*e.word_ptr(e.cs, 0xBAA4 + 2) = e.ds;
	e.add(*e.word_ptr(e.cs, 0xBAA4), e.cx);
	e.rep_movsb();
	e.pop(e.di);
	e.pop(e.si);
	e.pop(e.es);
	e.pop(e.ds);
	e.dx = *e.word_ptr(e.cs, 0xBA9C);
	e.inc(e.dx);
	e.cmp(*e.byte_ptr(e.cs, 0xBA9A), 0);
	if (e.jnz()) {
		goto loc_1BB63;
	}
	goto loc_1BC52;
	// ---------------------------------------------------------------------------

loc_1BB63:
	e.push(e.ds);
	e.push(e.es);
	e.push(e.di);
	e.xor8(e.ch, e.ch);
	e.cl = *e.byte_ptr(e.cs, 0xBA9A);
	e.di = 0x201;
	e.ax = e.ds;
	e.es = e.ax;
	e.ds = *e.word_ptr(e.cs, 0xBAA4 + 2);
	e.si = *e.word_ptr(e.cs, 0xBAA4);
	e.add(*e.word_ptr(e.cs, 0xBAA4), e.cx);
	e.rep_movsb();
	e.cl = *e.byte_ptr(e.cs, 0xBA9A);
	e.xor8(e.ch, e.ch);
	e.di = 1;
	e.add(*e.word_ptr(e.cs, 0xBAA4), e.cx);
	e.rep_movsb();
	e.cl = *e.byte_ptr(e.cs, 0xBA9A);
	e.di = 0x101;
	e.add(*e.word_ptr(e.cs, 0xBAA4), e.cx);
	e.rep_movsb();
	e.pop(e.di);
	e.pop(e.es);
	e.pop(e.ds);
	e.xor8(e.ch, e.ch);
	e.cl = *e.byte_ptr(e.cs, 0xBA9A);
	e.xor8(e.ah, e.ah);
	e.bx = 1;
loc_1BBB4:
	e.al                            = *e.byte_ptr(e.ds, e.bx + 0x200);
	e.si                            = e.ax;
	e.dl                            = *e.byte_ptr(e.ds, e.si + 0x301);
	*e.byte_ptr(e.ds, e.bx + 0x402) = e.dl;
	*e.byte_ptr(e.ds, e.si + 0x301) = e.bl;
	e.inc(e.bx);
	if (e.loop()) {
		goto loc_1BBB4;
	}
	e.dx = *e.word_ptr(e.cs, 0xBA9C);
	e.inc(e.dx);
	e.cx = 1;
loc_1BBD2:
	e.dec(e.dx);
	if (e.jnz()) {
		goto loc_1BBE1;
	}
loc_1BBD5:
	e.cmp(*e.byte_ptr(e.cs, 0xBA9B), 0);
	if (e.jz()) {
		goto locret_1BBE0;
	}
	goto start;
	// ---------------------------------------------------------------------------

locret_1BBE0:
	return;
	// ---------------------------------------------------------------------------

loc_1BBE1:
	e.push(e.ds);
	e.si = *e.word_ptr(e.cs, 0xBAA4 + 2);
	e.ds = e.si;
	e.si = *e.word_ptr(e.cs, 0xBAA4);
	e.lodsb();
	*e.word_ptr(e.cs, 0xBAA4) = e.si;
	e.pop(e.ds);
	e.bx = e.ax;
	e.cmp(*e.byte_ptr(e.ds, e.bx + 0x301), 0);
	if (e.jnz()) {
		goto loc_1BC01;
	}
	e.stosb();
	goto loc_1BBD2;
	// ---------------------------------------------------------------------------

loc_1BC01:
	e.bl = *e.byte_ptr(e.ds, e.bx + 0x301);
	e.xor16(e.ax, e.ax);
	e.push(e.ax);
	goto loc_1BC35;
	// ---------------------------------------------------------------------------

loop_x:
	e.bp = e.ax;
	e.cmp(*e.byte_ptr(e.ds, e.bp + 0x301), 0);
	if (e.jz()) {
		goto loc_1BC44;
	}
	e.cmp(e.bl, *e.byte_ptr(e.ds, e.bp + 0x301));
	if (e.ja()) {
		goto loc_1BC30;
	}
	e.al = e.bl;
	e.bl = *e.byte_ptr(e.ds, e.bp + 0x301);
loc_1BC22:
	e.bl = *e.byte_ptr(e.ds, e.bx + 0x402);
	e.or8(e.bl, e.bl);
	if (e.jz()) {
		goto loc_1BC42;
	}
	e.cmp(e.bl, e.al);
	if (e.jb()) {
		goto loc_1BC35;
	}
	goto loc_1BC22;
	// ---------------------------------------------------------------------------

loc_1BC30:
	e.bl = *e.byte_ptr(e.ds, e.bp + 0x301);

loc_1BC35:
	e.al = *e.byte_ptr(e.ds, e.bx + 0x100);
	e.ah = e.bl;
	e.push(e.ax);
	e.xor8(e.ah, e.ah);
	e.al = *e.byte_ptr(e.ds, e.bx);
	goto loop_x;
	// ---------------------------------------------------------------------------

loc_1BC42:
	e.ax = e.bp;
loc_1BC44:
	e.stosb();
	e.pop(e.ax);
	e.or16(e.ax, e.ax);
	if (e.jnz()) {
		goto loc_1BC4C;
	}
	goto loc_1BBD2;
	// ---------------------------------------------------------------------------

loc_1BC4C:
	e.bl = e.ah;
	e.xor8(e.ah, e.ah);
	goto loop_x;
	// ---------------------------------------------------------------------------

loc_1BC52:
	e.push(e.ds);
	e.push(e.es);
	e.cx = *e.word_ptr(e.cs, 0xBA9C);
	e.push(e.cx);
	e.ds = *e.word_ptr(e.cs, 0xBAA4 + 2);
	e.si = *e.word_ptr(e.cs, 0xBAA4);
	e.add(*e.word_ptr(e.cs, 0xBAA4), e.cx);
	e.rep_movsb();
	e.pop(e.cx);
	e.pop(e.es);
	e.pop(e.ds);
	goto loc_1BBD5;
}

} // namespace alpha_waves

#if REGAMES_GAME() == REGAMES_ALPHA_WAVES

namespace regames {

void detect_exe(const std::string& program_name_, PhysPt loadaddress_)
{
	alpha_waves::detect_exe(program_name_, loadaddress_);
}

void detect_code_run(Bitu cs_, Bitu ip_)
{
	alpha_waves::detect_code_run(cs_, ip_);
}
bool detect_call_begin(Bitu cs_, Bitu ip_)
{
	return alpha_waves::detect_call_begin(cs_, ip_);
}

} // namespace regames

#endif