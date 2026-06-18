#pragma once

#include <cstddef>
#include <utility>

namespace Netpp
{

template <typename Signature>
class MoveOnlyFunction;

template <typename R, typename... Args>
class MoveOnlyFunction<R(Args...)>
{
  static constexpr size_t SBO_SIZE = 64;
  static constexpr size_t SBO_ALIGN = alignof(std::max_align_t);

public:
  MoveOnlyFunction() = default;

  template <typename F>
  MoveOnlyFunction(F &&f)
  {
    using Decay = std::decay_t<F>;
    static_assert(std::is_move_constructible_v<Decay>, "Callback must be move constructible");
    static_assert(sizeof(Decay) <= SBO_SIZE && alignof(Decay) <= SBO_ALIGN,
                  "Callback must fit in SBO buffer (64 bytes, max_align_t alignment)");

    _invoke = [](void *storage, Args &&...args) -> R {
      return (*static_cast<Decay *>(storage))(std::forward<Args>(args)...);
    };
    _move = [](void *dst, void *src) { new (dst) Decay(std::move(*static_cast<Decay *>(src))); };
    _destroy = [](void *storage) { static_cast<Decay *>(storage)->~Decay(); };

    new (_buf) Decay(std::forward<F>(f));
  }

  MoveOnlyFunction(MoveOnlyFunction &&other) noexcept
  {
    if (!other._invoke)
    {
      _invoke = nullptr;
      return;
    }

    _invoke = other._invoke;
    _move = other._move;
    _destroy = other._destroy;

    if (_move)
    {
      _move(_buf, other._buf);
    }

    other._invoke = nullptr;
  }

  MoveOnlyFunction &operator=(MoveOnlyFunction &&other) noexcept
  {
    if (this != &other)
    {
      if (_destroy && _invoke)
      {
        _destroy(_buf);
      }

      _invoke = nullptr;
      if (other._invoke)
      {
        _invoke = other._invoke;
        _move = other._move;
        _destroy = other._destroy;

        if (_move)
        {
          _move(_buf, other._buf);
        }

        other._invoke = nullptr;
      }
    }
    return *this;
  }

  MoveOnlyFunction(const MoveOnlyFunction &) = delete;
  MoveOnlyFunction &operator=(const MoveOnlyFunction &) = delete;

  ~MoveOnlyFunction()
  {
    if (_destroy && _invoke)
    {
      _destroy(_buf);
    }
  }

  R operator()(Args... args) const
  {
    return _invoke(const_cast<char *>(_buf), std::forward<Args>(args)...);
  }

  explicit operator bool() const
  {
    return _invoke != nullptr;
  }

private:
  alignas(SBO_ALIGN) mutable char _buf[SBO_SIZE] = {};

  R (*_invoke)(void *, Args &&...args) = nullptr;
  void (*_move)(void *dst, void *src) = nullptr;
  void (*_destroy)(void *storage) = nullptr;
};

} // namespace Netpp
