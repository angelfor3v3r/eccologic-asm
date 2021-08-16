#pragma once

// Definitions below are shared across both the "encode" and "decode" APIs.

// Arguments for "cs_open".
struct CapstoneOpenArgs
{
    cs_arch m_arch;
    cs_mode m_mode;
};

const std::unordered_map< std::string_view, CapstoneOpenArgs > g_cs_args{
    // x86.
    { "x86-64", { CS_ARCH_X86, CS_MODE_64 } }, // x86 (64-bit).
    { "x86-32", { CS_ARCH_X86, CS_MODE_32 } }, // x86 (32-bit).
    { "x86-16", { CS_ARCH_X86, CS_MODE_16 } }, // x86 (16-bit).

    // ARM.
    { "aarch64", { CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN } } // ARM-64 (aka. AArch64); NOTE: Keystone doesn't support big endian ARM64 but Capstone does.
};

namespace api::detail
{
    inline const auto resp( const Json::Value &json, HttpStatusCode http_status = k200OK ) noexcept
    {
        const auto resp{ HttpResponse::newHttpJsonResponse( json ) };
        resp->setStatusCode( http_status );
        return resp;
    }

    inline const auto resp_err( const std::string& msg, std::string_view status, HttpStatusCode http_status, bool append_help = true ) noexcept
    {
        const std::string help{ ( append_help ) ? " See https://asm.eccologic.net/help for API help." : "" };
        Json::Value res;
        res[ "error" ][ "message" ] = msg + help;
        res[ "error" ][ "status"  ] = status.data();
        return resp( std::move( res ), http_status );
    }

    // TODO: Capstone supports "CS_OPT_MODE". Maybe it's faster than allocating a new Capstone state each time?

    // Decodes bytes for both API endpoints and returns two JOSN objects.
    inline std::optional< Json::Value > decode_bytes( csh cs, const uint8_t* bytes, size_t len )
    {
        const auto insn{ cs_malloc( cs ) };
        if( !insn )
        {
            return {};
        }

        // Now decode the bytes so we can give back information about them.
        Json::Value all_bytes, bytes_detail;
        uint64_t    addr{};
        size_t      decoded{};
        while( cs_disasm_iter( cs, &bytes, &len, &addr, insn ) )
        {
            // Add byte to partial/full instruction JSON byte array.
            Json::Value cur_bytes;
            const auto size{ insn->size };
            for( size_t i{}; i < size; ++i )
            {
                const auto byte{ fmt::format( "{:02X}", insn->bytes[ i ] ) };
                cur_bytes.append( byte );
                all_bytes.append( byte );
            }

            Json::Value info;
            info[ "address"  ] = fmt::format( "{:04X}", insn->address );
            info[ "size"     ] = size;
            info[ "bytes"    ] = cur_bytes;
            info[ "mnemonic" ] = insn->mnemonic;

            // Make hexidecimal numbers nicer by uppercasing them all.
            // Regex position 0 will have the "0x" prefix and position 1 will have a number.
            std::string      ops{ insn->op_str };
            const std::regex expr{ R"((?:0[xX])([0-9a-fA-F]+))" };
            for( std::sregex_iterator it{ ops.begin(), ops.end(), expr }; it != std::sregex_iterator{}; ++it )
            {
                const auto match{ *it };
                auto       str{ match.str( 1 ) };
                std::transform( str.cbegin(), str.cend(), str.begin(),
                    []( uint8_t ch )
                    {
                        return std::toupper( ch );
                    } );

                ops.replace( match.position( 1 ), str.length(), str );
            }

            info[ "operands" ] = ops;
            bytes_detail.append( std::move( info ) );

            ++decoded;
        }

        cs_free( insn, 1 );

        // Set up the final JSON result.
        Json::Value res;
        res[ "result" ][ "byte_count"   ] = decoded;
        res[ "result" ][ "bytes"        ] = all_bytes;
        res[ "result" ][ "bytes_detail" ] = bytes_detail;

        return { res };
    }
} // namespace api::detail

// API route handlers.
#include "api_encode.hpp"
#include "api_decode.hpp"