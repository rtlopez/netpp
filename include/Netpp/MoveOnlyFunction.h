#pragma once

#include <memory>
#include <utility>

namespace Netpp
{

template <typename Signature>
class MoveOnlyFunction;

template <typename R, typename... Args>
class MoveOnlyFunction<R(Args...)>
{
public:
  MoveOnlyFunction() = default;

  template <typename F>
  MoveOnlyFunction(F &&f)
      : _impl(std::make_unique<Model<std::decay_t<F>>>(std::forward<F>(f)))
  {
  }

  MoveOnlyFunction(MoveOnlyFunction &&) = default;
  MoveOnlyFunction &operator=(MoveOnlyFunction &&) = default;

  MoveOnlyFunction(const MoveOnlyFunction &) = delete;
  MoveOnlyFunction &operator=(const MoveOnlyFunction &) = delete;

  R operator()(Args... args) { return _impl->call(std::forward<Args>(args)...); }

  explicit operator bool() const { return _impl != nullptr; }

private:
  struct Concept
  {
    virtual ~Concept() = default;
    virtual R call(Args... args) = 0;
  };

  template <typename F>
  struct Model : Concept
  {
    F func;
    Model(F &&f) : func(std::move(f)) {}
    R call(Args... args) override { return func(std::forward<Args>(args)...); }
  };

  std::unique_ptr<Concept> _impl;
};

} // namespace Netpp
