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
    // Regex position 0 contains some prefix ("0x", "\x" or just a number) and position 1 contains JUST the number.
    std::vector< uint8_t > bytes;
    const std::regex       expr{ R"((?:0[xX]|\\[xX])*([0-9a-fA-F]+))" };
    for( std::sregex_iterator it{ code.begin(), code.end(), expr }; it != std::sregex_iterator{}; ++it )
    {
        // Convert the string to an integer.
        uint8_t    byte;
        const auto str{ ( *it ).str( 1 ) };
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
    csh cs{};

    // The lambda here gets ran on return (RAII).
    ScopeGuard cleanup{
        [ &cs ]() noexcept
        {
            if( cs )
            {
                cs_close( &cs );
            }
        }
    };

    // Set up Capstone.
    if( const auto err{ cs_open( found_cs_args->second.m_arch, found_cs_args->second.m_mode, &cs ) }; err != CS_ERR_OK )
    {
        return resp_err( "Internal Server Error (1).", "ServerError", k500InternalServerError );
    }

    // Let Capstone skip over "broken" instructions on its own.
    cs_option( cs, CS_OPT_SKIPDATA, CS_OPT_ON );

    // Now decode the bytes so we can give back information about them.
    const auto decode_res{ decode_bytes( cs, bytes.data(), bytes.size() ) };
    if( !decode_res )
    {
        return resp_err( "Internal Server Error (2).", "ServerError", k500InternalServerError );
    }

    // Did some error happen when disassembling?
    if( const auto ec{ cs_errno( cs ) }; ec != CS_ERR_OK )
    {
        return resp_err( cs_strerror( ec ), "InvalidAsmCode", k400BadRequest, false );
    }

    return resp( std::move( *decode_res ) );
}

} // namespace api