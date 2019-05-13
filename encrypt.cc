#include <cassert>

#include "common.h"

using namespace std;
using namespace seal;

vector<Plaintext>
clks_to_left_matrix(const vector<CLK> &clks, BatchEncoder &encoder) {
    size_t clksz = clks[0].size();

    size_t half_slot_count = encoder.slot_count() / 2;
    assert(half_slot_count % clksz == 0);
    assert(clks.size() <= half_slot_count); // FIXME relax this with chunking

    vector< vector<int64_t> > diag_matrix;
    for (size_t i = 0; i < clks.size(); ++i) {
        vector<int64_t> cpy(clks[i]);
        rotate(begin(cpy), begin(cpy) + (i % cpy.size()), end(cpy));
        diag_matrix.push_back(cpy);
    }

    // Transpose diag_matrix
    vector< vector<int64_t> > diag_matrix_tr(diag_matrix[0].size());
    for (auto &v : diag_matrix_tr)
        v.resize(diag_matrix.size());
    for (size_t i = 0; i < diag_matrix.size(); ++i)
        for (size_t j = 0; j < diag_matrix[0].size(); ++j)
            diag_matrix_tr[j][i] = diag_matrix[i][j];

    vector<Plaintext> ptxts(clksz);
    for (size_t i = 0; i < clksz; ++i) {
        vector<int64_t> cpy(diag_matrix_tr[i]);
        cpy.insert(end(cpy), begin(cpy), end(cpy));
        encoder.encode(cpy, ptxts[i]);
    }
    return ptxts;
}

template< template<typename> class C, typename T >
struct repeat {
    typename C<T>::const_iterator idx, begin, end;

    explicit repeat(const C<T> &seq)
        : idx(std::begin(seq)), begin(std::begin(seq)), end(std::end(seq)) { }

    T operator()() {
        T res = *idx++;
        if (idx == end)
            idx = begin;
        return res;
    }
};

vector<Plaintext>
clks_to_right_matrix(const vector<CLK> &clks, BatchEncoder &encoder) {
    assert(clks.size() > 0);
    int clksz = clks[0].size();
    CLK empty_clk(clksz, 0);

    int half_slot_count = encoder.slot_count() / 2;
    assert(half_slot_count % clksz == 0);
    int clks_per_col = half_slot_count / clksz;

    size_t nptxts = (clks.size() + 1) / 2; // ceil(clks.size() / 2.0)
    vector<Plaintext> ptxts(nptxts);
    for (size_t i = 0, j = 0; j < clks.size(); ++i, j += 2) {
        vector<int64_t> col(2 * clksz * clks_per_col);
        vector<int64_t>::iterator halfway = col.begin() + clksz * clks_per_col;
        generate(col.begin(), halfway, repeat(clks[j]));
        generate(halfway, col.end(), repeat(clks[j + 1]));
        encoder.encode(col, ptxts[i]);
    }
    // FIXME: Handle last CLK
    return ptxts;
}
