#include "main.hpp"

namespace api
{

using namespace detail;

HttpResponsePtr decode( const HttpRequestPtr& req ) noexcept
{
    const auto json{ req->jsonObject() };
    if( !json )
    {
        return resp_err( "Invalid JSON object or missing \"Content-Type\" request header.", "InvalidJson", k400BadRequest );
    }

    // Check keys & key types in the request JSON.
    if( !json->isMember( "arch" ) )
    {
        return resp_err( "JSON object is missing the \"arch\" key.", "MissingArchKey", k400BadRequest );
    }
    else if( !json->isMember( "code" ) )
    {
        return resp_err( "JSON object is missing the \"code\" key.", "MissingCodeKey", k400BadRequest );
    }

    // Resolve architecture value from the request JSON.
    const auto arch_key{ json->operator[]( "arch" ) };
    if( !arch_key.isString() )
    {
        return resp_err( "\"arch\" value must be a string.", "InvalidArchType", k400BadRequest );
    }

    const auto found_cs_args{ g_cs_args.find( arch_key.asString() ) };
    if( found_cs_args == g_cs_args.end() )
    {
        return resp_err( "Invalid \"arch\" value.", "InvalidArchValue", k400BadRequest );
    }

    // Resolve code string to encode from the request JSON.
    const auto code_key{ json->operator[]( "code" ) };
    if( !code_key.isString() )
    {
        return resp_err( "\"code\" value must be a string.", "InvalidCodeType", k400BadRequest );
    }

    const auto code{ code_key.asString() };
    if( code.empty() )
    {
        return resp_err( "\"code\" value must not be empty.", "InvalidCodeValue", k400BadRequest );
    }

    // Here we're going to parse the hex bytes into a vector.
    // Regex position 0 contains some prefix ("0x" or "\x") and position 1 contains the number.
    // TODO: I really should make this work with more number patterns.
    //       Theres still some issues to work out such as "0x550x123" not parsing the "0x" prefix correctly (it counts the 0 as a number from the capture).
    //       ... And maybe add support for parsing long numbers in 2-byte intervals (i.e. AABBCC = {0xAA, 0xBB, 0xCC}).
    //       But honestly this makes me question if im over-engineering this. Will it really be hard for people to just pass bytes with a prefix before each number (such as ';' or a space...).
    //       As much as I *want* to make this as dynamic as possible... I think being strict about the input string would be smarter and less bug-prone (but not as user-friendly?).
    //       Whatever... We'll figure out something eventually.
    std::vector< uint8_t > bytes;
    const std::regex       expr{ "(?:0[xX]|\\\\[xX])([0-9a-fA-F]+)" };
    for( std::sregex_iterator it{ code.begin(), code.end(), expr }; it != std::sregex_iterator{}; ++it )
    {
        // Convert the string to an integer.
        const auto str{ ( *it ).str( 1 ) };
        uint8_t byte;
        const auto [ _, ec ]{ std::from_chars( str.data(), str.data() + str.length(), byte, 16 ) };
        if( ec == std::errc::invalid_argument )
        {
            return resp_err( "\"code\" value (somehow) contained a non-number value.", "InvalidCodeNumber", k400BadRequest );
        }
        else if( ec == std::errc::result_out_of_range )
        {
            return resp_err( "\"code\" value contains a number that's out of byte range (must be between 0 and 0xFF).", "InvalidCodeNumberRange", k400BadRequest );
        }

        bytes.emplace_back( byte );
    }

    // Variables here MUST be cleaned up on exit if they're set.
    csh      cs{};
    cs_insn* insn{};

    // The lambda here gets ran on return (RAII).
    ScopeGuard cleanup{
        [ &insn, &cs ]() noexcept
        {
            if( insn )
            {
                cs_free( insn, 1 );
            }

            if( cs )
            {
                cs_close( &cs );
            }
        }
    };

    // Set up Capstone (We only allocate room for decoding one instruction, since that's all "cs_disasm_iter" needs).
    if( const auto err{ cs_open( found_cs_args->second.m_arch, found_cs_args->second.m_mode, &cs ) }; err != CS_ERR_OK )
    {
        return resp_err( "Internal Server Error (3).", "ServerError", k500InternalServerError );
    }

    insn = cs_malloc( cs );

    // Now decode the bytes so we can give back information about them.
    Json::Value all_bytes, bytes_detail;
    auto        dec_code{ (const uint8_t *)bytes.data() };
    const auto  byte_count{ bytes.size() };
    size_t      dec_size{ byte_count };
    uint64_t    addr{};
    while( cs_disasm_iter( cs, &dec_code, &dec_size, &addr, insn ) )
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
        const std::regex expr{ "(?:0[xX])([0-9a-fA-F]+)" };
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
    }

    // Did some error happen when disassembling?
    if( const auto ec{ cs_errno( cs ) }; ec != CS_ERR_OK )
    {
        // Clean up the capstone error.
        std::string err{ cs_strerror( ec ) };
        if( const auto first_delim{ err.find( '(' ) }; first_delim != std::string::npos )
        {
            if( const auto second_delim{ err.find( ')', first_delim + 1 ) }; second_delim != std::string::npos )
            {
                err.erase( first_delim - 1, ( second_delim - first_delim ) + 2 );
                err += '.';
            }
            else { err = ""; }
        }
        else { err = ""; }

        return resp_err( err, "InvalidAsmCode", k400BadRequest, false );
    }

    // Set up the final JSON result.
    Json::Value res;
    res[ "result" ][ "byte_count"   ] = byte_count;
    res[ "result" ][ "bytes"        ] = all_bytes;
    res[ "result" ][ "bytes_detail" ] = bytes_detail;

    return resp( std::move( res ) );
}

} // namespace api