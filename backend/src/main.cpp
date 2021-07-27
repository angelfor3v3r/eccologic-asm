#include "mimalloc-new-delete.h"
#include "main.hpp"

using namespace drogon;

#define ROUTE( name, method_and_filters, func ) app().registerHandler( name, func, method_and_filters )

// Supported keystone architectures.
const std::unordered_map< int32_t, ks_arch > g_keystone_archs{
    { 0, KS_ARCH_X86   }, // x86 architecture (including x86 & x86-64).
    { 1, KS_ARCH_ARM64 }, // ARM-64, also called AArch64.
    { 2, KS_ARCH_ARM   }, // ARM architecture (including Thumb & Thumb-2).
    { 3, KS_ARCH_MIPS  }  // Mips architecture.
};

// Supported keystone modes.
const std::unordered_map< int32_t, ks_mode > g_keystone_modes{
    // x86.
    { 0, KS_MODE_64 }, // 64-bit.
    { 1, KS_MODE_32 }, // 32-bit.
    { 2, KS_MODE_16 }, // 16-bit.

    // ARM & ARM-64.
    { 3, KS_MODE_ARM   }, // ARM mode.
    { 4, KS_MODE_THUMB }, // THUMB mode (including Thumb-2).
    { 5, KS_MODE_V8    }, // ARMv8 A32 encodings for ARM.

    // Mips.
    { 6,  KS_MODE_MIPS64   }, // Mips64.
    { 7,  KS_MODE_MIPS32   }, // Mips32.
    { 8,  KS_MODE_MIPS32R6 }, // Mips32r6.
    { 9,  KS_MODE_MIPS3    }, // Mips III.
    { 10, KS_MODE_MICRO    }  // MicroMips.
};

// Maps a Keystone architecture to a Capstone architecture.
const std::unordered_map< ks_arch, cs_arch > g_ks_to_cs_arch{
    { KS_ARCH_X86,   CS_ARCH_X86   }, // x86 architecture (including x86 & x86-64).
    { KS_ARCH_ARM64, CS_ARCH_ARM64 }, // ARM-64, also called AArch64.
    { KS_ARCH_ARM,   CS_ARCH_ARM   }, // ARM architecture (including Thumb & Thumb-2).
    { KS_ARCH_MIPS,  CS_ARCH_MIPS  }  // Mips architecture.
};

// Maps a Keystone mode to a Capstone mode.
const std::unordered_map< ks_mode, cs_mode > g_ks_to_cs_mode{
    // x86.
    { KS_MODE_64, CS_MODE_64 }, // Also valid for PPC...
    { KS_MODE_32, CS_MODE_32 },
    { KS_MODE_16, CS_MODE_16 },

    // ARM & ARM-64.
    { KS_MODE_ARM,   CS_MODE_ARM   },
    { KS_MODE_THUMB, CS_MODE_THUMB },
    { KS_MODE_V8,    CS_MODE_V8    },

    // Mips.
    { KS_MODE_MIPS64,   CS_MODE_MIPS64   },
    { KS_MODE_MIPS32,   CS_MODE_MIPS32   },
    { KS_MODE_MIPS32R6, CS_MODE_MIPS32R6 },
    { KS_MODE_MIPS3,    CS_MODE_MIPS3    },
    { KS_MODE_MICRO,    CS_MODE_MICRO    }
};

// Convert a string to a integral type.
template< class _T >
std::optional< _T > from_str( std::string_view str )
{
    _T res;
    if( const auto[ p, ec ]{ std::from_chars( str.data(), str.data() + str.length(), res ) }; ec == std::errc{} )
    {
        return {};
    }

    return res;
}

// Handle posts to "/api/encode".
Json::Value api_handle_encode( const HttpRequestPtr& req )
{
    Json::Value root;

    const auto json_error{
        [ &root ]( std::string_view msg, HttpStatusCode status )
        {
            Json::Value error;
            error[ "message" ] = msg.data();
            error[ "status" ]  = status;
            root[ "error" ] = error;
            return root;
        }
    };

    const auto json{ req->jsonObject() };
    if( !json )
    {
        return json_error( "Missing \"Content-Type\" header or invalid JSON object.", k400BadRequest );
    }

    // Check keys & key types.
    if( !json->isMember( "arch" ) )
    {
        return json_error( "JSON object is missing the \"arch\" key.", k400BadRequest );
    }
    else if( !json->isMember( "mode" ) )
    {
        return json_error( "JSON object is missing the \"mode\" key.", k400BadRequest );
    }
    else if( !json->isMember( "code" ) )
    {
        return json_error( "JSON object is missing the \"code\" key.", k400BadRequest );
    }

    // Resolve architecture value from json.
    const auto arch_key{ json->operator[]( "arch" ) };
    if( !arch_key.isUInt() )
    {
        return json_error( "\"arch\" key must be an unsigned integral value.", k400BadRequest );
    }

    const auto found_arch{ g_keystone_archs.find( arch_key.asUInt() ) };
    if( found_arch == g_keystone_archs.end() )
    {
        return json_error( "Invalid \"arch\" value.", k400BadRequest );
    }

    // Resolve mode value from json.
    const auto mode_key{ json->operator[]( "mode" ) };
    if( !mode_key.isUInt() )
    {
        return json_error( "\"mode\" key must be an unsigned integral value.", k400BadRequest );
    }

    const auto found_mode{ g_keystone_modes.find( mode_key.asUInt() ) };
    if( found_mode == g_keystone_modes.end() )
    {
        return json_error( "Invalid \"mode\" value.", k400BadRequest );
    }

    // TODO: !!! Check if mode can be opened for arch !!!

    // Resolve code string to encode.
    const auto code_key{ json->operator[]( "code" ) };
    if( !code_key.isString() )
    {
        return json_error( "\"code\" key must be a string value.", k400BadRequest );
    }

    // Set up Keystone.
    const auto arch{ found_arch->second };
    const auto mode{ found_mode->second };
    const auto code{ code_key.asString() };

    // TODO: Cache all valid ks_open types.
    //       Sanity check code string.
    ks_engine *ks;
    auto keystone_err{ ks_open( arch, mode, &ks ) };
    if( keystone_err != KS_ERR_OK )
    {
        return json_error( "Internal Server Error.", k500InternalServerError );
    }

    // TODO: Syntax...
    /*
            // Runtime option value (associated with ks_opt_type above)
        typedef enum ks_opt_value {
        	KS_OPT_SYNTAX_INTEL =   1 << 0, // X86 Intel syntax - default on X86 (KS_OPT_SYNTAX).
        	KS_OPT_SYNTAX_ATT   =   1 << 1, // X86 ATT asm syntax (KS_OPT_SYNTAX).
        	KS_OPT_SYNTAX_NASM  =   1 << 2, // X86 Nasm syntax (KS_OPT_SYNTAX).
        	KS_OPT_SYNTAX_MASM  =   1 << 3, // X86 Masm syntax (KS_OPT_SYNTAX) - unsupported yet.
        	KS_OPT_SYNTAX_GAS   =   1 << 4, // X86 GNU GAS syntax (KS_OPT_SYNTAX).
        	KS_OPT_SYNTAX_RADIX16 = 1 << 5, // All immediates are in hex format (i.e 12 is 0x12)
        } ks_opt_value;
    */

    // Encode the code string.
    uint8_t *enc;
    size_t  enc_size;
    size_t  enc_stat;
    if( ks_asm( ks, code.c_str(), 0, &enc, &enc_size, &enc_stat ) != KS_ERR_OK )
    {
        return json_error( std::format( "Invalid code: {}", ks_strerror( ks_errno( ks ) ) ), k500InternalServerError );
    }

    // Set up Capstone.
    csh cs;
    auto capstone_err{ cs_open( g_ks_to_cs_arch.find( arch )->second, g_ks_to_cs_mode.find( mode )->second, &cs ) };
    if( capstone_err != CS_ERR_OK )
    {
        ks_free( enc );
        ks_close( ks );
        return json_error( std::format( "Internal Server Error {}.", (int32_t)capstone_err ), k500InternalServerError );
    }

    // Now decode again so we can give back each instruction line.
    cs_insn *insn;
    const auto dec_count{ cs_disasm( cs, enc, enc_size, 0, 0, &insn ) };
    if( dec_count < 1 )
    {
        ks_free( enc );
        ks_close( ks );
        cs_close( &cs );
        return json_error( "Internal Server Error. 2", k500InternalServerError );
    }

    Json::Value json_decoded_instructions;
    for( size_t i{}; i < dec_count; ++i )
    {
        // json_decoded_instructions[ ]
    }

    // Set up the JSON result.
    Json::Value json_encoded_bytes;
    for( size_t i{}; i < enc_size; ++i )
    {
        json_encoded_bytes.append( enc[ i ] );
    }

    root[ "result" ][ "byte_count" ] = enc_size;
    root[ "result" ][ "bytes" ]      = json_encoded_bytes;

    ks_free( enc );
    ks_close( ks );
    cs_free( insn, dec_count );
    cs_close( &cs );

    return root;
}

int32_t __cdecl main( int32_t argc, char **argv, char **envp )
{
    ROUTE( "/api/encode", { Post },
        []( const HttpRequestPtr& req, std::function< void ( const HttpResponsePtr& )>&& callback )
        {
            //const Json::Value json;
            //json[ "result" ] = "error"
            //
            //const auto enc_type{ req.getParameter( "type" ) };
            //const auto enc_data{ req.getParameter( "data" ) };
            //
            ////resp->setStatusCode( k200OK );
            ////resp->setContentTypeCode( CT_APPLICATION_JSON );
            ////// resp->setBody( "Hello, World!" );
            //
            //callback( resp );

            //Json::Value json_params{ Json::objectValue };
            //auto params{ req->getParameters() };
            //for( const auto& [key, value] : params ) {
            //    Json::Value param;
            //    param[ "key" ] = key;
            //    param[ "value" ] = value;
            //    json_params.append( param );
            //}
            //
            //auto resp{ HttpResponse::newHttpJsonResponse( json_params ) };
            //callback( resp );

            callback( HttpResponse::newHttpJsonResponse( api_handle_encode( req ) ) );
        }
    );

    ROUTE( "/", { Get },
        []( const HttpRequestPtr& req, std::function< void ( const HttpResponsePtr& )>&& callback )
        {
            const auto resp{ HttpResponse::newHttpResponse() };
            resp->setStatusCode( k200OK );
            resp->setContentTypeCode( CT_TEXT_HTML );
            resp->setBody( "Hello, World!" );
            callback( resp );
        }
    );

    //app().registerHandler(
    //    "/hello_user",
    //    [](const HttpRequestPtr &req,
    //       std::function<void(const HttpResponsePtr &)> &&callback) {
    //        auto resp = HttpResponse::newHttpResponse();
    //        std::string name = req->getParameter("user");
    //        if (name == "")
    //            resp->setBody("Please tell me your name");
    //        else
    //            resp->setBody("Hello, " + name + "!");
    //        callback(resp);
    //    },
    //    {Get});

    LOG_INFO << "Drogon server running...";
    app().loadConfigFile( "drogon-config.json" ).run();

    return 1;
}