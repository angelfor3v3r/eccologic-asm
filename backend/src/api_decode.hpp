#pragma once

namespace api
{

// Handle POST requests to "/api/decode".
extern drogon::HttpResponsePtr decode( const drogon::HttpRequestPtr& req ) noexcept;

} // namespace api