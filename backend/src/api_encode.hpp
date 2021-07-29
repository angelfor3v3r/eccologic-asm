#pragma once

namespace api
{

// Handle posts to "/api/encode".
extern drogon::HttpResponsePtr encode( const drogon::HttpRequestPtr& req ) noexcept;

} // namespace api