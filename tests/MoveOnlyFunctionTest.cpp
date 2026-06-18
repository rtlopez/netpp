#include "Netpp/MoveOnlyFunction.h"
#include <gtest/gtest.h>

#include <memory>
#include <string>

using Netpp::MoveOnlyFunction;

// ── Default construction ────────────────────────────────────────────

TEST(MoveOnlyFunctionTest, DefaultConstructedIsEmpty)
{
  MoveOnlyFunction<void()> fn;
  EXPECT_FALSE(static_cast<bool>(fn));
}

// ── Construction from callable ──────────────────────────────────────

TEST(MoveOnlyFunctionTest, ConstructFromLambda)
{
  MoveOnlyFunction<int()> fn([] { return 42; });
  EXPECT_TRUE(static_cast<bool>(fn));
  EXPECT_EQ(fn(), 42);
}

TEST(MoveOnlyFunctionTest, ConstructFromStatefulLambda)
{
  int counter = 0;
  MoveOnlyFunction<void()> fn([&counter] { ++counter; });
  fn();
  fn();
  EXPECT_EQ(counter, 2);
}

TEST(MoveOnlyFunctionTest, ConstructFromLambdaWithArgs)
{
  MoveOnlyFunction<int(int, int)> fn([](int a, int b) { return a + b; });
  EXPECT_EQ(fn(3, 4), 7);
}

TEST(MoveOnlyFunctionTest, ConstructFromLambdaReturningVoid)
{
  bool called = false;
  MoveOnlyFunction<void()> fn([&called] { called = true; });
  fn();
  EXPECT_TRUE(called);
}

// ── Functor support ─────────────────────────────────────────────────

namespace
{
struct Doubler
{
  int operator()(int x) const { return x * 2; }
};
} // namespace

TEST(MoveOnlyFunctionTest, ConstructFromFunctor)
{
  MoveOnlyFunction<int(int)> fn(Doubler{});
  EXPECT_EQ(fn(5), 10);
}

// ── Move-only callable (unique_ptr capture) ─────────────────────────

TEST(MoveOnlyFunctionTest, MoveOnlyCallable)
{
  auto ptr = std::make_unique<int>(99);
  MoveOnlyFunction<int()> fn([p = std::move(ptr)]() { return *p; });
  EXPECT_EQ(fn(), 99);
}

// ── Move construction ───────────────────────────────────────────────

TEST(MoveOnlyFunctionTest, MoveConstruct)
{
  MoveOnlyFunction<int()> a([] { return 7; });
  MoveOnlyFunction<int()> b(std::move(a));

  EXPECT_TRUE(static_cast<bool>(b));
  EXPECT_EQ(b(), 7);
  EXPECT_FALSE(static_cast<bool>(a));
}

TEST(MoveOnlyFunctionTest, MoveConstructFromEmpty)
{
  MoveOnlyFunction<void()> a;
  MoveOnlyFunction<void()> b(std::move(a));

  EXPECT_FALSE(static_cast<bool>(a));
  EXPECT_FALSE(static_cast<bool>(b));
}

// ── Move assignment ─────────────────────────────────────────────────

TEST(MoveOnlyFunctionTest, MoveAssignToEmpty)
{
  MoveOnlyFunction<int()> a([] { return 10; });
  MoveOnlyFunction<int()> b;

  b = std::move(a);
  EXPECT_TRUE(static_cast<bool>(b));
  EXPECT_EQ(b(), 10);
  EXPECT_FALSE(static_cast<bool>(a));
}

TEST(MoveOnlyFunctionTest, MoveAssignToNonEmpty)
{
  MoveOnlyFunction<int()> a([] { return 1; });
  MoveOnlyFunction<int()> b([] { return 2; });

  b = std::move(a);
  EXPECT_TRUE(static_cast<bool>(b));
  EXPECT_EQ(b(), 1);
  EXPECT_FALSE(static_cast<bool>(a));
}

TEST(MoveOnlyFunctionTest, MoveAssignFromEmpty)
{
  MoveOnlyFunction<int()> a;
  MoveOnlyFunction<int()> b([] { return 5; });

  b = std::move(a);
  EXPECT_FALSE(static_cast<bool>(b));
  EXPECT_FALSE(static_cast<bool>(a));
}

TEST(MoveOnlyFunctionTest, SelfMoveAssign)
{
  MoveOnlyFunction<int()> fn([] { return 42; });
  auto &ref = fn;
  fn = std::move(ref);

  EXPECT_TRUE(static_cast<bool>(fn));
  EXPECT_EQ(fn(), 42);
}

// ── Destructor correctness ──────────────────────────────────────────

namespace
{
struct DtorTracker
{
  int *counter;
  explicit DtorTracker(int *c) : counter(c) {}
  DtorTracker(DtorTracker &&o) noexcept : counter(o.counter) { o.counter = nullptr; }
  DtorTracker &operator=(DtorTracker &&) = delete;
  ~DtorTracker()
  {
    if (counter)
      ++(*counter);
  }
  void operator()() const {}
};
} // namespace

TEST(MoveOnlyFunctionTest, DestructorCallsStoredCallableDestructor)
{
  int dtorCount = 0;
  {
    MoveOnlyFunction<void()> fn(DtorTracker{&dtorCount});
    // DtorTracker temporary is destroyed after construction, so count may be >0.
    // Reset to track only the MoveOnlyFunction's cleanup.
    dtorCount = 0;
  }
  EXPECT_EQ(dtorCount, 1);
}

TEST(MoveOnlyFunctionTest, DestructorNotCalledForEmpty)
{
  // Should not crash or invoke anything.
  MoveOnlyFunction<void()> fn;
}

TEST(MoveOnlyFunctionTest, MoveAssignDestroysOldCallable)
{
  int dtorCount = 0;
  MoveOnlyFunction<void()> fn(DtorTracker{&dtorCount});
  dtorCount = 0;

  fn = MoveOnlyFunction<void()>([] {});
  EXPECT_EQ(dtorCount, 1);
}

// ── Operator bool ───────────────────────────────────────────────────

TEST(MoveOnlyFunctionTest, BoolConversionAfterMove)
{
  MoveOnlyFunction<void()> a([] {});
  EXPECT_TRUE(static_cast<bool>(a));

  MoveOnlyFunction<void()> b(std::move(a));
  EXPECT_FALSE(static_cast<bool>(a));
  EXPECT_TRUE(static_cast<bool>(b));
}

// ── Various signatures ──────────────────────────────────────────────

TEST(MoveOnlyFunctionTest, ReturnsString)
{
  MoveOnlyFunction<std::string()> fn([] { return std::string("hello"); });
  EXPECT_EQ(fn(), "hello");
}

TEST(MoveOnlyFunctionTest, MultipleParameters)
{
  MoveOnlyFunction<int(int, int, int)> fn([](int a, int b, int c) { return a * b + c; });
  EXPECT_EQ(fn(2, 3, 4), 10);
}

TEST(MoveOnlyFunctionTest, ByValueParameter)
{
  MoveOnlyFunction<size_t(std::string)> fn([](std::string s) { return s.size(); });
  EXPECT_EQ(fn("test"), 4u);
}

// ── Reassignment with new callable ──────────────────────────────────

TEST(MoveOnlyFunctionTest, ReassignWithNewCallable)
{
  MoveOnlyFunction<int()> fn([] { return 1; });
  EXPECT_EQ(fn(), 1);

  fn = MoveOnlyFunction<int()>([] { return 2; });
  EXPECT_EQ(fn(), 2);
}

// ── Capturing state survives move ───────────────────────────────────

TEST(MoveOnlyFunctionTest, CapturedStateSurvivesMove)
{
  auto ptr = std::make_unique<int>(123);
  MoveOnlyFunction<int()> a([p = std::move(ptr)]() { return *p; });

  MoveOnlyFunction<int()> b(std::move(a));
  EXPECT_EQ(b(), 123);
  EXPECT_FALSE(static_cast<bool>(a));
}
