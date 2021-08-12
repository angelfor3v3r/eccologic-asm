#pragma once

namespace api
{

// Handle POST requests to "/api/encode".
extern drogon::HttpResponsePtr encode( const drogon::HttpRequestPtr& req ) noexcept;

} // namespace api