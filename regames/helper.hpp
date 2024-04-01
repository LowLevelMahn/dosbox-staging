#pragma once

#include <cstdint>
#include <string>
#include <vector>

constexpr size_t IDA_BASE = 0x10000;

inline uint8_t* by_IDA_EA_offset(uint8_t* game_image_begin_, size_t ida_ea_)
{
	return game_image_begin_ + (ida_ea_ - IDA_BASE);
};

std::string hexdump(const void* const ptr, int buflen, int width);
std::string hex_string(const void* const buffer_, const size_t& size_,
                       bool as_stream_ = false);

std::vector<uint8_t> read_binary_file( const std::string& filename_ );
void write_binary_file( const std::string& file_path_, const void* const data_, size_t size_ );
void write_string_file(const std::string& file_path_, const char* str_);

inline uint8_t lo( uint16_t value_ )
{
    return value_ & 0xFF;
}

inline uint8_t hi( uint16_t value_ )
{
    return value_ >> 8;
}

inline uint16_t lo( uint32_t value_ )
{
    return value_ & 0xFFFF;
}

inline uint16_t hi( uint32_t value_ )
{
    return value_ >> 16;
}

inline uint16_t swap( const uint16_t value_ )
{
    return ( value_ << 8 ) + ( value_ >> 8 );
}

inline uint32_t swap( const uint32_t value_ )
{
    const uint16_t lv = lo( value_ );
    const uint16_t hv = hi( value_ );
    return ( swap( lv ) << 16 ) + swap( hv );
}

uint8_t* stack_ptr(size_t offset_);

template <typename ValueType>
ValueType stack_value(size_t offset_)
{
    return *(ValueType*)stack_ptr(offset_);
}

#pragma pack(push, 1)
struct far_ptr_t {
    far_ptr_t(uint16_t segment_, uint16_t offset_)
	    : offset(offset_),
	      segment(segment_)
    {}

    uint16_t offset;
    uint16_t segment;
};
#pragma pack(pop)

inline uint32_t ptr16_to_offset32(const far_ptr_t& ptr16_)
{
    return ptr16_.segment * 16 + ptr16_.offset;
}

inline far_ptr_t offset32_to_ptr16(const uint32_t& offset32_)
{
    return {uint16_t(offset32_ / 16), uint16_t(offset32_ % 16)};
}

uint8_t* native_ptr(uint32_t ofs32_);
uint8_t* native_ptr(uint16_t seg_, uint16_t ofs_);
void* native_ptr(far_ptr_t ptr_);

std::string to_lower(const std::string& str_);
