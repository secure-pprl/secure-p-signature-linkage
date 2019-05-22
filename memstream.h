#pragma once

#include <istream>
#include <streambuf>

// Convenience for using buffers as streams
// Found here: https://stackoverflow.com/a/13059195
// and here: https://stackoverflow.com/a/13542996
struct membuf: std::streambuf {
    membuf(char *base, size_t size) {
        this->setp(base, base + size);
        this->setg(base, base, base + size);
    }
    size_t written() const { return this->pptr() - this->pbase(); }
    size_t read() const    { return this->gptr() - this->eback(); }
};

struct imemstream: virtual membuf, std::istream {
    imemstream(const char *base, size_t size)
        : membuf(const_cast<char *>(base), size)
        , std::istream(static_cast<std::streambuf *>(this)) {
    }
};

struct omemstream: virtual membuf, std::ostream {
    omemstream(char *base, size_t size)
        : membuf(base, size)
        , std::ostream(static_cast<std::streambuf *>(this)) {
    }
};
