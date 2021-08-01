#include "main.hpp"

using namespace drogon;

namespace api
{

// Arguments for "ks_open".
struct KeystoneOpenArgs
{
    ks_arch m_arch;
    ks_mode m_mode;
};

// Supported keystone architectures/modes.
const std::unordered_map< std::string_view, KeystoneOpenArgs > g_ks_args{
    // x86.
    { "x86-64", { KS_ARCH_X86, KS_MODE_64 } }, // x86 (64-bit).
    { "x86-32", { KS_ARCH_X86, KS_MODE_32 } }, // x86 (32-bit).
    { "x86-16", { KS_ARCH_X86, KS_MODE_16 } }, // x86 (16-bit).

    // ARM.
    { "aarch64", { KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN } } // AArch64 (AKA. ARM64),
};

// Supported syntax options (x86 only).
const std::unordered_map< int32_t, ks_opt_value > g_ks_syntax{
    { 0, KS_OPT_SYNTAX_INTEL }, // x86 Intel syntax.
    { 1, KS_OPT_SYNTAX_NASM  }, // x86 Nasm syntax.
    { 2, KS_OPT_SYNTAX_ATT   }  // x86 ATT asm syntax.
};

// Handle posts to "/api/encode".
HttpResponsePtr encode( const HttpRequestPtr& req ) noexcept
{
    const auto respond{
        [ &req ]( const Json::Value &json, HttpStatusCode http_status = k200OK ) noexcept ATTR_FORCEINLINE
        {
            const auto resp{ HttpResponse::newHttpJsonResponse( json ) };
            resp->setStatusCode( http_status );
            return resp;
        }
    };

    const auto respond_err{
        [ &respond ]( std::string_view msg, std::string_view status, HttpStatusCode http_status ) noexcept ATTR_FORCEINLINE
        {
            Json::Value error;
            error[ "message" ] = std::string{ msg } + " See https://asm.eccologic.net/help for API help.";
            error[ "status" ]  = status.data();
            return respond( std::move( error ), http_status );
        }
    };

    const auto json{ req->jsonObject() };
    if( !json )
    {
        return respond_err( "Invalid JSON object or missing \"Content-Type\" request header.", "InvalidJson", k400BadRequest );
    }

    // Check keys & key types in the request JSON.
    if( !json->isMember( "arch" ) )
    {
        return respond_err( "JSON object is missing the \"arch\" key.", "InvalidJson", k400BadRequest );
    }
    else if( !json->isMember( "code" ) )
    {
        return respond_err( "JSON object is missing the \"code\" key.", "InvalidJson", k400BadRequest );
    }

    // Resolve architecture value from the request JSON.
    const auto arch_key{ json->operator[]( "arch" ) };
    if( !arch_key.isString() )
    {
        return respond_err( "\"arch\" key value must be a string.", "InvalidJsonValue", k400BadRequest );
    }

    const auto found_ks_args{ g_ks_args.find( arch_key.asString() ) };
    if( found_ks_args == g_ks_args.end() )
    {
        return respond_err( "Invalid \"arch\" value.", "InvalidJsonValue", k400BadRequest );
    }

    // Is there a syntax key?
    std::optional< ks_opt_value > syntax;
    const auto                    arch{ found_ks_args->second.m_arch };
    const auto                    x86{ arch == KS_ARCH_X86 };
    if( json->isMember( "syntax" ) )
    {
        // Special case for x86 (The syntax key is optional, you don't have to specifiy it and the code will default to Intel syntax).
        if( x86 )
        {
            // Resolve syntax option value from the request JSON.
            const auto syntax_key{ json->operator[]( "syntax" ) };
            if( !syntax_key.isUInt() )
            {
                return respond_err( "\"syntax\" key value must be an unsigned integral.", "InvalidJsonValue", k400BadRequest );
            }

            const auto found_syntax{ g_ks_syntax.find( syntax_key.asUInt() ) };
            if( found_syntax == g_ks_syntax.end() )
            {
                return respond_err( "Invalid \"syntax\" key value.", "InvalidJsonValue", k400BadRequest );
            }

            // Only fill the syntax value in if it's not the Intel syntax.
            if( const auto value{ found_syntax->second }; value != KS_OPT_SYNTAX_INTEL )
            {
                syntax = value;
            }
        }
        else
        {
            return respond_err( "The \"syntax\" key is only valid for the x86 architecture.", "InvalidJsonValue", k400BadRequest );
        }
    }

    // Resolve code string to encode from the request JSON.
    const auto code_key{ json->operator[]( "code" ) };
    if( !code_key.isString() )
    {
        return respond_err( "\"code\" key value must be a string.", "InvalidJsonValue", k400BadRequest );
    }

    const auto code{ code_key.asString() };
    if( code.empty() )
    {
        return respond_err( "\"code\" key string value must not be empty.", "InvalidJsonValue", k400BadRequest );
    }

    // The lambda here gets ran on return (RAII). Variables here MUST be cleaned up on exit if they're set.
    uint8_t*   enc_code{};
    ks_engine* ks{};
    csh        cs{};
    cs_insn*   insn{};
    const auto cleanup{ sg::make_scope_guard(
        [ &enc_code, &ks, &insn, &cs ]() noexcept ATTR_FORCEINLINE
        {
            if( enc_code )
            {
                ks_free( enc_code );
            }

            if( ks )
            {
                ks_close( ks );
            }

            if( insn )
            {
                cs_free( insn, 1 );
            }

            if( cs )
            {
                cs_close( &cs );
            }
        }
    ) };

    // Set up Keystone.
    // TODO: Well... Maybe it would be a good idea to cache each mode & arch = ks_ptr into an unordered_map.
    //       But it seems like keystone does a pretty good job of initializing all "heavy" code at once... I think?
    //       Either way, I should profile this in heavy production cases.
    const auto mode{ found_ks_args->second.m_mode };
    if( const auto err{ ks_open( arch, mode, &ks ) }; err != KS_ERR_OK )
    {
        return respond_err( std::format( "Assembling failed: {}", ks_strerror( err ) ), "ServerError", k500InternalServerError );
    }

    // Set ASM syntax (only supported for the x86 architecture).
    if( x86 && syntax )
    {
        if( ks_option( ks, KS_OPT_SYNTAX, *syntax ) != KS_ERR_OK )
        {
            return respond_err( "Internal Server Error.", "ServerError", k500InternalServerError );
        }
    }

    // Encode the code string.
    size_t enc_size, enc_statements;
    if( ks_asm( ks, code.c_str(), 0, &enc_code, &enc_size, &enc_statements ) != KS_ERR_OK )
    {
        return respond_err( std::format( "Disassembling failed: {}.", ks_strerror( ks_errno( ks ) ) ), "InvalidAsmCode", k500InternalServerError );
    }

    // Set up Capstone (We only allocate room for decoding one instruction, since that's all "cs_disasm_iter" needs).
    const auto cs_args{ g_cs_args.find( found_ks_args->first ) };
    if( const auto err{ cs_open( cs_args->second.m_arch, cs_args->second.m_mode, &cs ) }; err != CS_ERR_OK )
    {
        return respond_err( "Internal Server Error.", "ServerError", k500InternalServerError );
    }

    insn = cs_malloc( cs );

    // Now decode again so we can give back information.
    Json::Value all_bytes, bytes_detail;
    auto        dec_code{ (const uint8_t *)enc_code };
    size_t      dec_size{ enc_size };
    uint64_t    addr{};
    while( cs_disasm_iter( cs, &dec_code, &dec_size, &addr, insn ) )
    {
        Json::Value info, bytes;
        const auto size{ insn->size };
        for( size_t i{}; i < size; ++i )
        {
            const auto byte{ insn->bytes[ i ] };
            bytes.append( byte ); // Add byte to partial instruction JSON byte array.
            all_bytes.append( byte ); // Add byte to full instruction JSON byte array.
        }

        info[ "bytes" ]    = bytes;
        info[ "address"  ] = insn->address;
        info[ "size"     ] = size;
        info[ "mnemonic" ] = insn->mnemonic;
        info[ "operands" ] = insn->op_str;

        bytes_detail.append( std::move( info ) );
    }

    // Set up the final JSON result.
    Json::Value res;
    res[ "result" ][ "byte_count" ]   = enc_size;
    res[ "result" ][ "bytes" ]        = all_bytes;
    res[ "result" ][ "bytes_detail" ] = bytes_detail;

    return respond( std::move( res ) );
}

} // namespace api