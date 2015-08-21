#include <iostream>
#include <string>

namespace test {
class simple {
private:
    bool mno_plan, mskip, mtodo, mprt_nums;
    int muse_nums, mcur_test, mtest_skip, mtest_ok, mtest_notok;

public:
    simple ()
        : mno_plan (true), mskip (false), mtodo (false), mprt_nums (false),
          muse_nums (0), mcur_test (0),
          mtest_skip (0), mtest_ok (0), mtest_notok (0) { }

    simple (int n)
        : mno_plan (false), mskip (false), mtodo (false), mprt_nums (true),
          muse_nums (n), mcur_test (0),
          mtest_skip (0), mtest_ok (0), mtest_notok (0) { }

    void skip () { mskip = true; }
    void todo () { mtodo = true; }

    bool ok (bool tst, std::string desc)
    {
        if (mprt_nums) {
            std::cout << "1.." << muse_nums << std::endl;
            mprt_nums = false;
        }
        ++mcur_test;
        if (mskip) {
            ++mtest_skip;
            std::cout << "ok " << mcur_test << " # SKIP";
            if (! desc.empty ()) {
                std::cout << " " << desc;
            }
        }
        else if (tst) {
            ++mtest_ok;
            std::cout << "ok " << mcur_test;
            if (! desc.empty ()) {
                std::cout << " - " << desc;
            }
        }
        else {
            ++mtest_notok;
            std::cout << "not ok " << mcur_test;
            if (! desc.empty ()) {
                std::cout << " - " << desc;
            }
            if (mtodo) {
                std::cout << " # TODO";
            }
        }
        std::cout << std::endl;
        mskip = false;
        mtodo = false;
        return tst;
    }

    void diag (std::string s)
    {
        std::cout << "# ";
        for (auto c : s) {
            std::cout << c;
            if (c == '\n') {
                std::cout << "# ";
            }
        }
        std::cout << std::endl;
    }

    bool done_testing ()
    {
        if (mno_plan) {
            muse_nums = mcur_test;
            mprt_nums = true;
        }
        if (mprt_nums) {
            std::cout << "1.." << mcur_test << std::endl;
            mprt_nums = false;
        }
        return muse_nums == mtest_ok + mtest_skip ? EXIT_SUCCESS : EXIT_FAILURE;
    }
};
} //namespace test
