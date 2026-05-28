#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace Netpp
{

class RingBuffer
{
public:
  explicit RingBuffer(size_t capacity = 0) : _buffer(capacity), _head(0), _tail(0), _size(0)
  {
  }

  // Returns the number of readable bytes in the buffer.
  size_t size() const
  {
    return _size;
  }

  // Returns the total capacity of the underlying storage.
  size_t capacity() const
  {
    return _buffer.size();
  }

  size_t available() const
  {
    return _buffer.size() - _size;
  }

  bool empty() const
  {
    return _size == 0;
  }

  // --- Write interface ---

  // Append data to the buffer. If there is not enough free space,
  // the buffer linearizes and grows automatically.
  void write(std::span<const uint8_t> data)
  {
    if (data.empty())
    {
      return;
    }

    expand(data.size());

    size_t cap = _buffer.size();

    // How much fits from _tail to the end of the storage?
    size_t tailToEnd = cap - _tail;

    if (data.size() <= tailToEnd)
    {
      std::memcpy(_buffer.data() + _tail, data.data(), data.size());
    }
    else
    {
      std::memcpy(_buffer.data() + _tail, data.data(), tailToEnd);
      std::memcpy(_buffer.data(), data.data() + tailToEnd, data.size() - tailToEnd);
    }

    _tail = (_tail + data.size()) % cap;
    _size += data.size();
  }

  // --- Zero-copy read interface ---

  // Returns a span to the first contiguous readable segment starting
  // at _head. This is the block you can pass directly to send().
  // If the data wraps around, only the portion up to the end of the
  // internal storage is returned — call again after consume() for the rest.
  std::span<const uint8_t> readableSpan() const
  {
    if (_size == 0)
    {
      return {};
    }

    size_t cap = _buffer.size();
    size_t contiguous = std::min(_size, cap - _head);
    return {_buffer.data() + _head, contiguous};
  }

  // Mark `n` bytes as consumed (e.g. after a successful or partial send()).
  // Advances the read head. `n` must be <= size().
  void consume(size_t n)
  {
    if (n == 0)
    {
      return;
    }

    if (n > _size)
    {
      n = _size;
    }

    _head = (_head + n) % _buffer.size();
    _size -= n;

    // Reset positions when buffer is empty to maximize contiguous space.
    if (_size == 0)
    {
      _head = 0;
      _tail = 0;
    }
  }

  // --- Writable span interface (zero-copy write) ---

  // Returns a span to the first contiguous writable region.
  // After writing into this span, call commitWrite() with the actual
  // number of bytes written.
  std::span<uint8_t> writableSpan()
  {
    size_t cap = _buffer.size();
    size_t free = cap - _size;
    if (free == 0)
    {
      return {};
    }

    size_t contiguous = std::min(free, cap - _tail);
    return {_buffer.data() + _tail, contiguous};
  }

  // Commit `n` bytes that were written directly into writableSpan().
  void commitWrite(size_t n)
  {
    size_t cap = _buffer.size();
    size_t free = cap - _size;
    if (n > free)
    {
      n = free;
    }

    _tail = (_tail + n) % cap;
    _size += n;
  }

  // Linearize the readable data so that the entire content is in one
  // contiguous block. After this call, readableSpan().size() == size().
  void linearize()
  {
    if (_size == 0)
    {
      _head = 0;
      _tail = 0;
      return;
    }

    if (_head == 0)
    {
      return; // already linear
    }

    size_t cap = _buffer.size();
    if (_head + _size <= cap)
    {
      // Data doesn't wrap — just shift to front.
      std::memmove(_buffer.data(), _buffer.data() + _head, _size);
    }
    else
    {
      // Data wraps — use a temporary copy.
      std::vector<uint8_t> tmp(_size);
      size_t firstPart = cap - _head;
      std::memcpy(tmp.data(), _buffer.data() + _head, firstPart);
      std::memcpy(tmp.data() + firstPart, _buffer.data(), _size - firstPart);
      std::memcpy(_buffer.data(), tmp.data(), _size);
    }

    _head = 0;
    _tail = _size;
  }

  void clear()
  {
    _buffer.clear();
    _head = 0;
    _tail = 0;
    _size = 0;
  }

  // Ensure at least `needed` bytes of free space are available.
  // Linearizes and/or grows the buffer as necessary.
  void expand(size_t needed)
  {
    if (available() >= needed)
    {
      return;
    }

    // Linearize first so the grow is a simple resize.
    linearize();

    size_t newCap = _buffer.size();
    size_t required = _size + needed;
    while (newCap < required)
    {
      newCap = newCap == 0 ? 4096 : newCap + 4096; // grow by 4KB increments
    }

    _buffer.resize(newCap);
    // _head is 0, _tail is _size after linearize.
  }

  std::vector<uint8_t> _buffer;
  size_t _head;
  size_t _tail;
  size_t _size;
};

} // namespace Netpp