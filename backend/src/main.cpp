#include "mimalloc-new-delete.h"
#include "main.hpp"

using namespace drogon;

int32_t __cdecl main( int32_t argc, char **argv, char **envp ) noexcept
{
    const auto fw{ &app() };

    // Load the Drogon config first.
    fw->loadConfigFile( "./drogon-config.json" );

    // Set up API routes.
    fw->registerHandler( "/api/encode",
        []( const HttpRequestPtr& req, std::function< void ( const HttpResponsePtr& )>&& callback )
        {
            callback( api::encode( req ) );
        },
        { Post } );

    fw->registerHandler( "/api/decode",
        []( const HttpRequestPtr& req, std::function< void ( const HttpResponsePtr& )>&& callback )
        {
            callback( api::encode( req ) );
        },
        { Post } );

    // Since the primary frontend is a Single-page application (SPA) then I must serve the client-side frontend always.
    // The actual 404 is handled elsewhere.
    fw->setCustom404Page( HttpResponse::newFileResponse( std::format( "{}/{}", app().getDocumentRoot(), app().getHomePage() ) ), false );

    // Run the web server.
    LOG_INFO << "Drogon server running...";
    fw->run();

    return 1;
}