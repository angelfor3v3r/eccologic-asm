#include "main.hpp"

namespace detail
{

// Test for a callback with a void return & no arguments.
template< class _Callback >
concept ValidCallback = std::same_as< decltype( std::declval< _Callback&& >()() ), void > && std::is_invocable_r_v< void, _Callback >;

} // namespace detail

// Runs the passed callback function on scope exit (RAII & function must have a void return type with no arguments).
template< detail::ValidCallback _Callback >
class ScopeGuard
{
public:
    using callback_type = _Callback;

public:
    ScopeGuard( callback_type&& callback ) noexcept :
        m_callback{ std::forward< callback_type >( callback ) }
    {}

    ~ScopeGuard() noexcept
    {
        m_callback();
    }

    // No moving/copying.
    ScopeGuard( const ScopeGuard& ) = delete;
    ScopeGuard( ScopeGuard&& ) = delete;
    ScopeGuard& operator=( const ScopeGuard& ) = delete;
    ScopeGuard& operator=( ScopeGuard&& ) = delete;

private:
    callback_type m_callback;
};