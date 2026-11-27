#include "adapter_iptc/exceptions/iptc_exception.h"

#include <cerrno>
#include <gtest/gtest.h>

TEST(IptcExceptionTest, ErrorNumberIsZeroWhenNotGiven)
{
    const IptcException exception("message");

    EXPECT_EQ(exception.errorNumber(), 0);
    EXPECT_STREQ(exception.what(), "message");
}

TEST(IptcExceptionTest, KeepsTheErrorNumber)
{
    const IptcException exception("iptc_commit(mangle): Bad rule", EINVAL);

    EXPECT_EQ(exception.errorNumber(), EINVAL);
}
