#include "mem.h"
#include "regs.h"
#include "paging.h"

#include "../regames/regames.hpp"

#include <algorithm>
#include <array>
#include <cstdint>

namespace {

#pragma pack(push, 1)
struct far_ptr_t {
	uint16_t offset;
	uint16_t segment;
};

#pragma pack ( push, 1 )

struct struct1_t
{
  uint8_t unknown1[18];
  uint8_t bender_range; // 0-24, cropped to 0-24 by MT32
  uint8_t unknown2[2];
  uint8_t byte_15;
  uint8_t unknown3[3];
  uint8_t byte_19;   
  uint8_t unknown4[14];
  uint8_t byte_28;  
  uint8_t unknown5[12];
  uint8_t byte_35;   
  uint8_t unknown6[14];
  uint8_t program;
  uint8_t volume;
  uint8_t pan;
};

static_assert(sizeof(struct struct1_t) == 0x47u, "wrong size");
static_assert(offsetof(struct struct1_t, unknown1) == 0x0u, "wrong offset");
static_assert(offsetof(struct struct1_t, bender_range) == 0x12u, "wrong offset");
static_assert(offsetof(struct struct1_t, unknown2) == 0x13u, "wrong offset");
static_assert(offsetof(struct struct1_t, byte_15) == 0x15u, "wrong offset");
static_assert(offsetof(struct struct1_t, unknown3) == 0x16u, "wrong offset");
static_assert(offsetof(struct struct1_t, byte_19) == 0x19u, "wrong offset");   
static_assert(offsetof(struct struct1_t, unknown4) == 0x1Au, "wrong offset");
static_assert(offsetof(struct struct1_t, byte_28) == 0x28u, "wrong offset");  
static_assert(offsetof(struct struct1_t, unknown5) == 0x29u, "wrong offset");
static_assert(offsetof(struct struct1_t, byte_35) == 0x35u, "wrong offset");   
static_assert(offsetof(struct struct1_t, unknown6) == 0x36u, "wrong offset");
static_assert(offsetof(struct struct1_t, program) == 0x44u, "wrong offset");
static_assert(offsetof(struct struct1_t, volume) == 0x45u, "wrong offset");
static_assert(offsetof(struct struct1_t, pan) == 0x46u, "wrong offset");

// this code from clvn fits the struct1_t partially (at least in the program,volume,pan offset)
// http://forum.stunts.hu/index.php?topic=2570.msg86134#msg86134
/*
char *vce = findResource(vceBuf, seq->voices[i].id);

if (vce == NULL) {
  seq->voices[i].enabled = false;
}
else {
  seq->voices[i].enabled   = true;
  seq->voices[i].transpose = vce[0x10];
  seq->voices[i].hasHits   = vce[0x25];
  seq->voices[i].channel   = vce[0x43];
  seq->voices[i].program   = vce[0x44]; ==> struct1_t::program
  seq->voices[i].volume    = vce[0x45]; ==> struct1_t::volume
  seq->voices[i].pan       = vce[0x46]; ==> struct1_t::pan
} 
*/

struct struct2_t
{
  uint8_t unknown1[3];
  uint8_t key_note_number1;
  uint8_t velocity;
  uint8_t unknown2;
  uint8_t key_note_number2;
  uint8_t unknown3[13];
  uint16_t word_14;
  uint8_t unknown4[6];
  uint16_t word_1C;
  uint8_t unknown5[4];
  uint8_t byte_22;
};

static_assert(sizeof(struct struct2_t) == 0x23u, "wrong size");
static_assert(offsetof(struct struct2_t, unknown1) == 0x0u, "wrong offset");
static_assert(offsetof(struct struct2_t, key_note_number1) == 0x3u, "wrong offset");
static_assert(offsetof(struct struct2_t, velocity) == 0x4u, "wrong offset");   
static_assert(offsetof(struct struct2_t, unknown2) == 0x5u, "wrong offset");
static_assert(offsetof(struct struct2_t, key_note_number2) == 0x6u, "wrong offset");  
static_assert(offsetof(struct struct2_t, unknown3) == 0x7u, "wrong offset");   
static_assert(offsetof(struct struct2_t, word_14) == 0x14u, "wrong offset");
static_assert(offsetof(struct struct2_t, unknown4) == 0x16u, "wrong offset");
static_assert(offsetof(struct struct2_t, word_1C) == 0x1Cu, "wrong offset");
static_assert(offsetof(struct struct2_t, unknown5) == 0x1Eu, "wrong offset");
static_assert(offsetof(struct struct2_t, byte_22) == 0x22u, "wrong offset");

#pragma pack(pop)

std::string to_lower(const std::string &str_)
{
	std::string data = str_;
	std::transform(data.begin(), data.end(), data.begin(), [](unsigned char c) {
		return std::tolower(c);
	});
	return data;
}

uint8_t *stunts_image_begin = nullptr;

enum class DrvType { Undefined, MT15, AD15, PC15, TD15 };

DrvType driver_type = DrvType::Undefined;

// https://github.com/LowLevelMahn/UnifiedMT15/blob/2947002fe4a839e7e4a3d66a27e5f3d6ff38587c/MT15.asm#L177
const std::array<size_t, 23> drv_local_jump_offset{0x00, 0x03, 0x06, 0x09, 0x0C,
                                                   0x0F, 0x12, 0x15, 0x18, 0x1B,
                                                   0x1E, 0x21, 0x24, 0x27, 0x2A,
                                                   0x2D, 0x30, 0x33, 0x36, 0x39,
                                                   0x3C, 0x3F, 0x42};

uint8_t *driver_ptr = nullptr;

std::string hex_string(const void *const p_buffer, const size_t &p_size,
                       const bool &p_as_stream)
{
	std::string tmp;
	if (p_size != 0) {
		const size_t byte_width = p_as_stream ? 2 : 3;

		const size_t string_size = (p_size * byte_width) -
		                           (p_as_stream ? 0 : 1);
		tmp.resize(string_size, ' ');

		const uint8_t *const in_buffer = (uint8_t *)p_buffer;
		uint8_t *const out_buffer      = (uint8_t *)&tmp[0];

		for (size_t i = 0; i < p_size; ++i) {
			const char hex_digits[] = "0123456789ABCDEF";
			const uint8_t value     = in_buffer[i];
			char *const chr = (char *)(out_buffer + (i * byte_width));
			chr[0]          = hex_digits[value >> 4];
			chr[1]          = hex_digits[value & 0xF];
		}
	}
	return tmp;
}

} // namespace

namespace stunts {

void detect_exe(const std::string& program_name_, PhysPt loadaddress_)
{
	if (to_lower(program_name_) == "game.exe") {
		// gets set on every game.exe start
		// loadseg = exe image start, right after PSP
		stunts_image_begin = MemBase + loadaddress_;
		driver_ptr         = nullptr;
		driver_type        = DrvType::Undefined;

		std::array<uint8_t, 8> buffer{};
		memcpy(buffer.data(), stunts_image_begin, buffer.size());
		const std::array<uint8_t, 8> original{
		        0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x12, 0x57, 0x56};

		if (buffer != original) {
			LOG_MSG("!!!!!!!! STUNTS: not the correct game.exe");
		}

		LOG_MSG("!!!!!!!! STUNTS: game.exe startet");
	}
}

DrvType get_driver_type(const std::string &file_path_)
{
	auto name = to_lower(file_path_);
	if (name == "pc15.drv")
		return DrvType::PC15;
	if (name == "ad15.drv")
		return DrvType::AD15;
	if (name == "mt15.drv")
		return DrvType::MT15;
	if (name == "td15.drv")
		return DrvType::TD15;
	return DrvType::Undefined;
}

void detect_drv_load(const std::string &file_path_)
{
	if (!stunts_image_begin) {
		return;
	}

	if (driver_type == DrvType::Undefined) {
		driver_type = get_driver_type(file_path_);

		if (driver_type != DrvType::Undefined) {
			LOG_MSG("!!!!!!!! STUNTS: driver = %s", file_path_.c_str());
		}
	}
}

void detect_code_run(Bitu cs_, Bitu ip_)
{
	if (!stunts_image_begin) {
		return;
	}

	if (driver_ptr) {
		return;
	}

	const uint8_t* current = MemBase + PhysicalMake(cs_, ip_);
	// from game_mod3.idb
	//   seg027:08A0, EA: 0x37970, Base: 0x10000
	const size_t init_offset = 0x37970 - 0x10000;
	const uint8_t *init_done = stunts_image_begin + init_offset;

	if (current == init_done) {
		// then we are here
		//
		// mov audiodriverbinary.offs, ax
		// mov audiodriverbinary.segm, dx
		/*
		or file-offset: 0x2A200
		0x0000000000000000:  A3 9A 4E          mov word ptr [0x4e9a], ax
		<-- offset 0x0000000000000003:  89 16 9C 4E       mov word ptr
		[0x4e9c], dx <-- segment 0x0000000000000007:  C6 06 E0 A1 7F mov
		byte ptr [0xa1e0], 0x7f 0x000000000000000c:  C6 06 D8 A1 7F mov
		byte ptr [0xa1d8], 0x7f 0x0000000000000011:  0B C2 or  ax, dx
		0x0000000000000013:  75 03             jne 0x18
		0x0000000000000015:  E9 CA 00          jmp 0xe2
		...
		*/

		{
			std::array<uint8_t, 8> buffer{};
			memcpy(buffer.data(), current, buffer.size());
			const std::array<uint8_t, 8> original{
			        0xA3, 0x9A, 0x4E, 0x89, 0x16, 0x9C, 0x4E, 0xC6};

			if (buffer != original) {
				LOG_MSG("!!!!!!!! STUNTS: its not the driver init done code!");
				return;
			}
		}

		driver_ptr = MemBase + PhysicalMake(reg_dx, reg_ax);

#if 0
		{
			// check the driver code
			std::array<uint8_t, 8> buffer{};
			memcpy(buffer.data(), driver_ptr, buffer.size());
			const std::array<uint8_t, 8> original{...};
		}
#endif

		LOG_MSG("!!!!!!!! STUNTS: driver init done");
	}
}

uint8_t *stack_ptr(size_t offset_)
{
	return MemBase + PhysicalMake(SegValue(ss), offset_);
}

template <typename ValueType>
ValueType stack_value(size_t offset_)
{
	return *(ValueType *)stack_ptr(offset_);
}

void on_tsub3_begin()
{
	uint16_t bp = reg_sp - 2;

	/*
	better names in the drv.c port
	mpu_command1_ = word ptr  6 // channel
	struct1_  = dword ptr  8
	key_note_number_ = word ptr  0Ch // key_note_number_
	velocity_ = word ptr  0Eh // velocity_
	struct2_  = dword ptr  10h
	*/
	uint16_t channel = stack_value<uint16_t>(bp + 6);
	far_ptr_t struct1_ = stack_value<far_ptr_t>(bp + 8);
	uint16_t key_note_number_ = stack_value<uint16_t>(bp + 0xC);
	uint16_t velocity_ = stack_value<uint16_t>(bp + 0xE);
	far_ptr_t struct2_ = stack_value<far_ptr_t>(bp + 0x10);

	auto struct1_ofs32 = PhysicalMake(struct1_.segment, struct1_.offset);
	auto struct2_ofs32 = PhysicalMake(struct2_.segment, struct2_.offset);

	struct2_t* struct1_ptr = (struct2_t*)(MemBase + struct1_ofs32);
	struct1_t* struct2_ptr = (struct1_t*)(MemBase + struct2_ofs32);

	LOG_MSG("!!!!!!!! STUNTS: tsub3: channel: %x, struct1_: %x, key_note_number_: %x, velocity_: %x, struct2_: %x",
	        channel,
	        struct1_ofs32,
	        key_note_number_,
	        velocity_,
	        struct2_ofs32);

	/*
	C-Port:

	struct1_->key_note_number1 = LO(key_note_number_);
	struct1_->key_note_number2 = LO(key_note_number_);
	struct1_->velocity = ( struct2_->byte_15 == 0) ? 127 : LO(velocity_);

	send_note_on_event_midi_msg(midi_channel_, key_note_number_, struct1_->velocity);
	*/

	LOG_MSG("!!!!!!!! STUNTS:       struct1_{key_note_number1: %u, key_note_number2: %u, velocity: %u}, struct2_.byte_15: %u",
	        struct1_ptr->key_note_number1,
	        struct1_ptr->key_note_number2,
	        struct1_ptr->velocity,
	        struct2_ptr->byte_15);
}

void on_tsub4_begin()
{
	uint16_t bp = reg_sp - 2;
	/*
	channel_	= word ptr  6
	struct_	= dword ptr  8
	*/

	uint16_t channel_    = stack_value<uint16_t>(bp + 6);
	far_ptr_t struct_    = stack_value<far_ptr_t>(bp + 8);

	auto struct_ofs32     = PhysicalMake(struct_.segment, struct_.offset);
	struct2_t* struct_ptr = (struct2_t*)(MemBase + struct_ofs32);

	LOG_MSG("!!!!!!!! STUNTS: tsub4: channel_: %u, struct_: %x, struct_->key_note_number2: %u", channel_, struct_ofs32, struct_ptr->key_note_number2);
}

void on_tsub6_begin()
{
	uint16_t bp = reg_sp - 2;
	/*
	unknown1_	= word ptr  6
	unknown2_	= word ptr  8
	mpu_command_	= word ptr  0Ah
	// better names in drv.c

channel_, uint16_t unknown2_, uint16_t controller_value_

	*/
	uint16_t channel_    = stack_value<uint16_t>(bp + 6);
	uint16_t unknown2_    = stack_value<uint32_t>(bp + 8);
	uint16_t controller_value_ = stack_value<uint32_t>(bp + 0xA);

	LOG_MSG("!!!!!!!! STUNTS: tsub6: channel_: %u, unknown2_: %u, controller_value_: 0x%X", channel_, unknown2_, controller_value_);
}

// uint16_t channel_, uint16_t unknown2_, uint16_t controller_nr_, uint16_t controller_value_

void on_tsub7_begin()
{
	uint16_t bp = reg_sp - 2;
	/*
	channel_	= word ptr  6
	unknown2_	= word ptr  8
	controller_nr_	= word ptr  0Ah
	controller_value_ = word ptr  0Ch
	*/
	uint16_t channel_    = stack_value<uint16_t>(bp + 6);
	uint16_t unknown2_    = stack_value<uint16_t>(bp + 8);
	uint16_t controller_nr_ = stack_value<uint16_t>(bp + 0xA);
	uint16_t controller_value_ = stack_value<uint16_t>(bp + 0xC);

	LOG_MSG("!!!!!!!! STUNTS: tsub7: channel_: %u, unknown2_: %u, controller_nr_: %u, controller_value_: 0x%X", 
		channel_, unknown2_, controller_nr_, controller_value_);
}

void on_tsub8_begin()
{
	uint16_t bp       = reg_sp - 2;
	uint16_t unknown0 = stack_value<uint16_t>(bp + 6);

	LOG_MSG("!!!!!!!! STUNTS: tsub8: unknown0: %u", unknown0);
}

void on_tsub9_begin()
{
	uint16_t bp = reg_sp - 2;

	// arg_0   = word ptr  6
	// arg_2   = word ptr  8
	// arg_4   = word ptr  0Ah
	uint16_t arg_0 = stack_value<uint16_t>(bp + 6);
	uint16_t arg_2 = stack_value<uint16_t>(bp + 8);
	uint16_t arg_4 = stack_value<uint16_t>(bp + 0xA);

	LOG_MSG("!!!!!!!! STUNTS: tsub9: arg0: %u, arg_2: %u, arg_4: %u", arg_0, arg_2, arg_4);
}

void on_tsub10_begin()
{
	uint16_t bp      = reg_sp - 2;
	uint16_t channel = stack_value<uint16_t>(bp + 6);

	LOG_MSG("!!!!!!!! STUNTS: tsub10: channel: %u", channel);
}

void on_tsub11_begin()
{
	uint16_t bp = reg_sp - 2;

	/*
	mpu_command_  = word ptr  6
	unknown1		= word ptr  8
	unknown2		= word ptr  0Ah
	buffer_   = dword ptr  0Ch
	*/
	uint16_t channel_ = stack_value<uint16_t>(bp + 6);
	uint16_t unknown1 = stack_value<uint16_t>(bp + 8);
	uint16_t unknown2_maybe_segment = stack_value<uint16_t>(bp + 0xA);
	far_ptr_t buffer_ = stack_value<far_ptr_t>(bp + 0xC);

	auto buffer_ofs32     = PhysicalMake(buffer_.segment, buffer_.offset);
	struct1_t* buffer_ptr = (struct1_t*)(MemBase + buffer_ofs32);

	LOG_MSG("!!!!!!!! STUNTS: tsub11: channel_: %x, unknown1: %x, unknown2_maybe_segment: %x, buffer_: %x", 
		channel_, unknown1, unknown2_maybe_segment, buffer_ofs32);

	/*
	C-Port of the function uses:
		channel_
		buffer_->program
		buffer_->bender_range
		buffer_->volume
		buffer_->pan
	*/

	LOG_MSG("!!!!!!!! STUNTS:        buffer{program: %u, bender_range: %u, volume: %u, pan: %u}",
	        buffer_ptr->program,
	        buffer_ptr->bender_range,
	        buffer_ptr->volume,
	        buffer_ptr->pan);
}

void on_tsub13_begin()
{
	uint16_t bp = reg_sp - 2;

	/*
	mpu_command_  = word ptr  6
	buffer1_  = dword ptr  8
	buffer2_  = dword ptr  0Ch 
	better names in drv.c
	*/
	uint16_t channel_ = stack_value<uint16_t>(bp + 6);
	far_ptr_t buffer1_ = stack_value<far_ptr_t>(bp + 8);
	far_ptr_t buffer2_ = stack_value<far_ptr_t>(bp + 0xC);

	auto buffer1_ofs32 = PhysicalMake(buffer1_.segment, buffer1_.offset);
	auto buffer2_ofs32 = PhysicalMake(buffer2_.segment, buffer2_.offset);

	struct2_t* buffer1 = (struct2_t*)(MemBase + buffer1_ofs32);
	struct1_t* buffer2 = (struct1_t*)(MemBase + buffer2_ofs32);
	
	//buffer1_ofs32 is channel oriented
	//buffer2_ofs32 is channel oriented

	LOG_MSG("!!!!!!!! STUNTS: tsub13: channel_: %x, buffer1_: %x, buffer2_: %x", 
		channel_, buffer1_ofs32, buffer2_ofs32);

	LOG_MSG("!!!!!!!! STUNTS:        buffer1{byte_22: %u, key_note_number1: %u, key_note_number2: %u, velocity: %u, word_1C: %u, word_14: %u}, buffer2{byte_28: %u, byte_19: %u, byte_35: %u}",
	        buffer1->byte_22,
	        buffer1->key_note_number1,
	        buffer1->key_note_number2,
	        buffer1->velocity,
	        buffer1->word_1C,
	        buffer1->word_14,
	        buffer2->byte_28,
	        buffer2->byte_19,
	        buffer2->byte_35);
}

void on_tsub21_begin()
{
	uint16_t bp = reg_sp - 2;
	// size_   = word ptr  6
	// buffer_ = dword ptr  8
	uint16_t size    = stack_value<uint16_t>(bp + 6);
	far_ptr_t buffer = stack_value<far_ptr_t>(bp + 8); // ofs:seg

	const uint8_t* content = MemBase +
	                         PhysicalMake(buffer.segment,
	                                                       buffer.offset);
	const std::string hex = hex_string(content, size, false);
	LOG_MSG("!!!!!!!! STUNTS: tsub21: size: %u, buffer: {%s}", size, hex.c_str());
}

void on_tsub22_begin()
{
	if (driver_type == DrvType::MT15) {
		uint16_t bp = reg_sp - 2;

		// mt32_plb = dword ptr  6
		far_ptr_t buffer = stack_value<far_ptr_t>(bp + 6); // ofs:seg

		const uint8_t *content = MemBase +
		                         PhysicalMake(buffer.segment, buffer.offset);
		const std::string hex = hex_string(content, 1271, false);

		LOG_MSG("!!!!!!!! STUNTS: tsub22: should be MT32.PLB content with MT15.DRV: {%s}",
		        hex.c_str());
	}
}

bool detect_call_begin(Bitu cs_, Bitu ip_)
{
	if (!driver_ptr) {
		return false;
	}

	uint8_t *dest = MemBase + PhysicalMake(cs_, ip_);

	for (size_t func = 0; func < drv_local_jump_offset.size(); ++func) {
		if (dest == driver_ptr + drv_local_jump_offset[func]) {
			
			switch (driver_type) {
			case DrvType::MT15: {
				// these are empty implementations in MT15
				if (func == 5 || func == 16) {
					return false;
				}
			} break;
			case DrvType::PC15: {
				// these are empty implementations in PC15
				if (func == 4 || func == 7 || func == 8 || func == 9 || func == 11 || func == 20 || func == 21) {
					return false;
				}
			} break;
			}
		
			//LOG_MSG("!!!!!!!! STUNTS: tsub%u called", func);

			switch (func) {
			case 3: on_tsub3_begin(); break;
			case 4: on_tsub4_begin(); break;
			case 6: on_tsub6_begin(); break;
			case 7: on_tsub7_begin(); break;
			case 8: on_tsub8_begin(); break; // verify
			case 9: on_tsub9_begin(); break; // not in use
			case 10: on_tsub10_begin(); break;
			case 11: on_tsub11_begin(); break;
			case 13: on_tsub13_begin(); break;
			case 21: on_tsub21_begin(); break;
			case 22: on_tsub22_begin(); break;
			default: LOG_MSG("!!!!!!!! STUNTS: tsub%u called", func);
			}
		}
	}

	return false;
}

} // namespace stunts

#if REGAMES_GAME() == REGAMES_STUNTS

namespace regames {

void detect_exe(const std::string& program_name_, PhysPt loadaddress_)
{
	stunts::detect_exe(program_name_, loadaddress_);
}

void detect_code_run(Bitu cs_, Bitu ip_)
{
	stunts::detect_code_run(cs_, ip_);
}
bool detect_call_begin(Bitu cs_, Bitu ip_)
{
	return stunts::detect_call_begin(cs_, ip_);
}

} // namespace regames

#endif