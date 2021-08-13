#include "main.hpp"

namespace api
{

using namespace detail;

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
    { "aarch64", { KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN } } // AArch64 (AKA. ARM64).
};

// Supported syntax options (x86 only).
const std::unordered_map< std::string_view, ks_opt_value > g_ks_syntax{
    { "intel", KS_OPT_SYNTAX_INTEL }, // x86 Intel syntax.
    { "nasm",  KS_OPT_SYNTAX_NASM  }, // x86 Nasm syntax.
    { "att",   KS_OPT_SYNTAX_ATT   }  // x86 ATT asm syntax.
};

HttpResponsePtr encode( const HttpRequestPtr& req ) noexcept
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

    const auto found_ks_args{ g_ks_args.find( arch_key.asString() ) };
    if( found_ks_args == g_ks_args.end() )
    {
        return resp_err( "Invalid \"arch\" value.", "InvalidArchValue", k400BadRequest );
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
            if( !syntax_key.isString() )
            {
                return resp_err( "\"syntax\" key value must be a string.", "InvalidSyntaxType", k400BadRequest );
            }

            const auto found_syntax{ g_ks_syntax.find( syntax_key.asString() ) };
            if( found_syntax == g_ks_syntax.end() )
            {
                return resp_err( "Invalid \"syntax\" key value.", "InvalidSyntaxValue", k400BadRequest );
            }

            // Only fill the syntax value in if it's not the Intel syntax.
            if( const auto value{ found_syntax->second }; value != KS_OPT_SYNTAX_INTEL )
            {
                syntax = value;
            }
        }
        else
        {
            return resp_err( "The \"syntax\" key is only valid for the x86 architecture.", "InvalidSytnaxKey", k400BadRequest );
        }
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

    // Variables here MUST be cleaned up on exit if they're set.
    uint8_t*   enc_code{};
    ks_engine* ks{};
    csh        cs{};
    cs_insn*   insn{};

    // The lambda here gets ran on return (RAII).
    ScopeGuard cleanup{
        [ &enc_code, &ks, &insn, &cs ]() noexcept
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
    };

    // Set up Keystone.
    // TODO: Well... Maybe it would be a good idea to cache each mode & arch = ks_ptr into an unordered_map.
    //       But it seems like keystone does a pretty good job of initializing all "heavy" code at once... I think?
    //       Either way, I should profile this in heavy production cases.
    const auto mode{ found_ks_args->second.m_mode };
    if( const auto err{ ks_open( arch, mode, &ks ) }; err != KS_ERR_OK )
    {
        return resp_err( "Internal Server Error (1).", "ServerError", k500InternalServerError );
    }

    // Set ASM syntax (only supported for the x86 architecture).
    if( x86 && syntax )
    {
        if( ks_option( ks, KS_OPT_SYNTAX, *syntax ) != KS_ERR_OK )
        {
            return resp_err( "Internal Server Error (2).", "ServerError", k500InternalServerError );
        }
    }

    // Encode the code string.
    size_t enc_size, enc_statements;
    if( ks_asm( ks, code.c_str(), 0, &enc_code, &enc_size, &enc_statements ) != KS_ERR_OK )
    {
        // Clean-up the keystone error.
        std::string err{ ks_strerror( ks_errno( ks ) ) };
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

    // Set up Capstone (We only allocate room for decoding one instruction, since that's all "cs_disasm_iter" needs).
    const auto found_cs_args{ g_cs_args.find( found_ks_args->first ) };
    if( const auto err{ cs_open( found_cs_args->second.m_arch, found_cs_args->second.m_mode, &cs ) }; err != CS_ERR_OK )
    {
        return resp_err( "Internal Server Error (3).", "ServerError", k500InternalServerError );
    }

    insn = cs_malloc( cs );

    // Now decode again so we can give back information.
    Json::Value all_bytes, bytes_detail;
    auto        dec_code{ (const uint8_t *)enc_code };
    size_t      dec_size{ enc_size };
    uint64_t    addr{};
    while( cs_disasm_iter( cs, &dec_code, &dec_size, &addr, insn ) )
    {
        // Add byte to partial/full instruction JSON byte array.
        Json::Value bytes;
        const auto size{ insn->size };
        for( size_t i{}; i < size; ++i )
        {
            const auto byte{ fmt::format( "{:02X}", insn->bytes[ i ] ) };
            bytes.append( byte );
            all_bytes.append( byte );
        }

        Json::Value info;
        info[ "address"  ] = fmt::format( "{:04X}", insn->address );
        info[ "size"     ] = size;
        info[ "bytes"    ] = bytes;
        info[ "mnemonic" ] = insn->mnemonic;

        // Make numbers nicer.
        std::string      ops{ insn->op_str };
        const std::regex expr{ "(?:0[xX])([0-9a-fA-F]+)" };
        for( std::sregex_iterator it{ ops.begin(), ops.end(), expr }; it != std::sregex_iterator{}; ++it )
        {
            // We use match/position 1 to skip the non-capture group.
            const auto match{ *it };
            auto       str{ match.str( 1 ) };

            // Make the matched string uppercase.
            std::transform( str.cbegin(), str.cend(), str.begin(),
                []( uint8_t ch )
                {
                    return std::toupper( ch );
                } );

            // Now replace them in the original string.
            ops.replace( match.position( 1 ), str.length(), str );
        }

        info[ "operands" ] = ops;

        bytes_detail.append( std::move( info ) );
    }

    // Set up the final JSON result.
    Json::Value res;
    res[ "result" ][ "byte_count"   ] = enc_size;
    res[ "result" ][ "bytes"        ] = all_bytes;
    res[ "result" ][ "bytes_detail" ] = bytes_detail;

    return resp( std::move( res ) );
}

} // namespace api