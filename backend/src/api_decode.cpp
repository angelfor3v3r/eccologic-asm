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
        return resp_err( "\"arch\" key value must be a string.", "InvalidArchType", k400BadRequest );
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
        return resp_err( "\"code\" key value must be a string.", "InvalidCodeType", k400BadRequest );
    }

    const auto code{ code_key.asString() };
    if( code.empty() )
    {
        return resp_err( "\"code\" key string value must not be empty.", "InvalidCodeValue", k400BadRequest );
    }

    // Here we're going to parse the hex bytes into a vector.
    std::vector< uint8_t > bytes;

    // TODO: Parse hex values...
    // Valid delimiters: " " | "," | ";" | "\n" | "\x"
    // Valid prefixes: "0x" | "\x"
    // More than one of the same delimiter in a row should be ignored if possible.

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

    // // Now decode the bytes so we can give back information about them.
    // Json::Value bytes_detail;
    // auto        dec_code{ (const uint8_t *)bytes.data() };
    // size_t      dec_size{ bytes.size() };
    // uint64_t    addr{};
    // while( cs_disasm_iter( cs, &dec_code, &dec_size, &addr, insn ) )
    // {
    // }

    // Set up the final JSON result.
    Json::Value res;
    // res[ "result" ][ "bytes_detail" ] = bytes_detail;

    return resp( std::move( res ) );
}

} // namespace api