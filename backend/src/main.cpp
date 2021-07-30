#include "mimalloc-new-delete.h"
#include "main.hpp"

using namespace drogon;

int32_t __cdecl main( int32_t argc, char **argv, char **envp )
{
    // Defines a route with "const HttpRequestPtr& req" and "std::function< void ( const HttpResponsePtr& )>&& callback" already defined.
    // NOTE: You must use a global by-reference capture for this to work.
    #define ROUTE( name, method_and_filters, func ) \
        app().registerHandler( name, []( const HttpRequestPtr& req, std::function< void ( const HttpResponsePtr& )>&& callback ){ func(); }, method_and_filters )

    ROUTE( "/api/encode", { Post },
        [ & ]() noexcept ATTR_FORCEINLINE
        {
            callback( api::encode( req ) );
        } );

    ROUTE( "/api/decode", { Post },
        [ & ]() noexcept ATTR_FORCEINLINE
        {
            // callback( api::decode( req ) );
        } );

    #undef ROUTE

    LOG_INFO << "Drogon server running...";
    app().loadConfigFile( "./drogon-config.json" ).run();

    return 1;
}