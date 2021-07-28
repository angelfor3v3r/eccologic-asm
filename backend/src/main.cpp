#include "mimalloc-new-delete.h"
#include "main.hpp"

using namespace drogon;

// Supported keystone architectures.
const std::unordered_map< int32_t, ks_arch > g_ks_archs{
    { 0, KS_ARCH_X86   }, // x86 architecture (including x86 & x86-64).

    // TODO: Rework these to have better modes.. I need support little/big endian with ease.
    // { 1, KS_ARCH_ARM64 }, // ARM-64, also called AArch64.
    // { 2, KS_ARCH_ARM   }, // ARM architecture (including Thumb & Thumb-2).
    // { 3, KS_ARCH_PPC   }, // PowerPC architecture.
    // { 3, KS_ARCH_MIPS  }  // Mips architecture.
};

// Supported keystone modes.
const std::unordered_map< int32_t, ks_mode > g_ks_modes{
    // x86.
    { 0, KS_MODE_64 }, // 64-bit.
    { 1, KS_MODE_32 }, // 32-bit.
    { 2, KS_MODE_16 }, // 16-bit.

    // TODO: Rework these to have better modes.. I need support little/big endian with ease.
    // // ARM & ARM-64.
    // { 3, KS_MODE_ARM   }, // ARM mode.
    // { 4, KS_MODE_THUMB }, // THUMB mode (including Thumb-2).
    // { 5, KS_MODE_V8    }, // ARMv8 A32 encodings for ARM.

    // // Mips.
    // { 6,  KS_MODE_MIPS64   }, // Mips64.
    // { 7,  KS_MODE_MIPS32   }, // Mips32.
    // { 8,  KS_MODE_MIPS32R6 }, // Mips32r6.
    // { 9,  KS_MODE_MIPS3    }, // Mips III.
    // { 10, KS_MODE_MICRO    }  // MicroMips.
};

// Supported syntax options.
const std::unordered_map< int32_t, ks_opt_value > g_ks_syntax{
    { 0, KS_OPT_SYNTAX_INTEL }, // x86 Intel syntax.
    { 1, KS_OPT_SYNTAX_NASM  }, // x86 Nasm syntax.
    { 2, KS_OPT_SYNTAX_ATT   }  // x86 ATT asm syntax.
};

// Maps a Keystone architecture to a Capstone architecture.
const std::unordered_map< ks_arch, cs_arch > g_ks_to_cs_arch{
    { KS_ARCH_X86,   CS_ARCH_X86   }, // x86 architecture (including x86 & x86-64).

    // TODO: Rework these to have better modes.. I need support little/big endian with ease.
    // { KS_ARCH_ARM64, CS_ARCH_ARM64 }, // ARM-64, also called AArch64.
    // { KS_ARCH_ARM,   CS_ARCH_ARM   }, // ARM architecture (including Thumb & Thumb-2).
    // { KS_ARCH_MIPS,  CS_ARCH_MIPS  }  // Mips architecture.
};

// Maps a Keystone mode to a Capstone mode.
const std::unordered_map< ks_mode, cs_mode > g_ks_to_cs_mode{
    // x86.
    { KS_MODE_64, CS_MODE_64 }, // NOTE: This is also valid for PPC...
    { KS_MODE_32, CS_MODE_32 },
    { KS_MODE_16, CS_MODE_16 },

    // TODO: Rework these to have better modes.. I need support little/big endian with ease.
    // // ARM & ARM-64.
    // { KS_MODE_ARM,   CS_MODE_ARM   },
    // { KS_MODE_THUMB, CS_MODE_THUMB },
    // { KS_MODE_V8,    CS_MODE_V8    },

    // // Mips.
    // { KS_MODE_MIPS64,   CS_MODE_MIPS64   },
    // { KS_MODE_MIPS32,   CS_MODE_MIPS32   },
    // { KS_MODE_MIPS32R6, CS_MODE_MIPS32R6 },
    // { KS_MODE_MIPS3,    CS_MODE_MIPS3    },
    // { KS_MODE_MICRO,    CS_MODE_MICRO    }
};

// Handle posts to "/api/encode".
HttpResponsePtr api_handle_encode( const HttpRequestPtr& req )
{
    const auto respond{
        [ &req ]( const Json::Value &json, HttpStatusCode http_status = k200OK )
        {
            const auto resp{ HttpResponse::newHttpJsonResponse( json ) };
            resp->setStatusCode( http_status );
            return resp;
        }
    };

    const auto respond_err{
        [ &respond ]( std::string_view msg, std::string_view status, HttpStatusCode http_status )
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
        return respond_err( "Invalid JSON object or missing \"Content-Type\" header", "InvalidJson", k400BadRequest );
    }

    // Check keys & key types in the request JSON.
    if( !json->isMember( "arch" ) )
    {
        return respond_err( "JSON object is missing the \"arch\" key.", "InvalidJson", k400BadRequest );
    }
    else if( !json->isMember( "mode" ) )
    {
        return respond_err( "JSON object is missing the \"mode\" key.", "InvalidJson", k400BadRequest );
    }
    else if( !json->isMember( "code" ) )
    {
        return respond_err( "JSON object is missing the \"code\" key.", "InvalidJson", k400BadRequest );
    }

    // Resolve architecture value from the request JSON.
    const auto arch_key{ json->operator[]( "arch" ) };
    if( !arch_key.isUInt() )
    {
        return respond_err( "\"arch\" key value must be an unsigned integral.", "InvalidJsonValue", k400BadRequest );
    }

    const auto found_arch{ g_ks_archs.find( arch_key.asUInt() ) };
    if( found_arch == g_ks_archs.end() )
    {
        return respond_err( "Invalid \"arch\" value.", "InvalidJsonValue", k400BadRequest );
    }

    // Is there a syntax key?
    std::optional< ks_opt_value > syntax;
    const auto                    arch{ found_arch->second };
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

    // Resolve mode value from the request JSON.
    const auto mode_key{ json->operator[]( "mode" ) };
    if( !mode_key.isUInt() )
    {
        return respond_err( "\"mode\" key value must be an unsigned integral.", "InvalidJsonValue", k400BadRequest );
    }

    const auto found_mode{ g_ks_modes.find( mode_key.asUInt() ) };
    if( found_mode == g_ks_modes.end() )
    {
        return respond_err( "Invalid \"mode\" key value.", "InvalidJsonValue", k400BadRequest );
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
    ) };

    // Set up Keystone.
    // TODO: Well... Maybe it would be a good idea to cache each mode & arch = ks_ptr into an unordered_map.
    //       But it seems like keystone does a pretty good job of initializing all "heavy" code at once... I think?
    //       Either way, I should profile this in heavy production cases.
    const auto mode{ found_mode->second };
    if( const auto err{ ks_open( arch, mode, &ks ) }; err != KS_ERR_OK )
    {
        return respond_err( std::format( "Assembling failed: {} {} {}", ks_strerror( err ), (int32_t)arch, (int32_t)mode ), "ServerError", k500InternalServerError );
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

    // Set up Capstone.
    if( const auto err{ cs_open( g_ks_to_cs_arch.find( arch )->second, g_ks_to_cs_mode.find( mode )->second, &cs ) }; err != CS_ERR_OK )
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

    return respond( res );
}

int32_t __cdecl main( int32_t argc, char **argv, char **envp )
{
    #define ROUTE( name, method_and_filters, func ) app().registerHandler( name, func, method_and_filters )

    ROUTE( "/api/encode", { Post },
        []( const HttpRequestPtr& req, std::function< void ( const HttpResponsePtr& )>&& callback )
        {
            callback( api_handle_encode( req ) );
        } );

    ROUTE( "/", { Get },
        []( const HttpRequestPtr& req, std::function< void ( const HttpResponsePtr& )>&& callback )
        {
            const auto resp{ HttpResponse::newHttpResponse() };
            resp->setStatusCode( k200OK );
            resp->setContentTypeCode( CT_TEXT_HTML );
            resp->setBody( "Hello, World!" );
            callback( resp );
        } );

    #undef ROUTE

    LOG_INFO << "Drogon server running...";
    app().loadConfigFile( "drogon-config.json" ).run();

    return 1;
}