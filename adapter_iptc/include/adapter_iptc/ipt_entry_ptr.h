#ifndef IPT_ENTRY_PTR_H
#define IPT_ENTRY_PTR_H

#include <cstdlib>
#include <memory>

struct ipt_entry;

/* LEARN: an ipt_entry is a variable-length buffer (header, matches, target), so it is allocated
   with calloc and owned with std::free as its deleter. Whoever holds an IptEntryPtr owns the rule
   buffer: RuleMapper::toEntry() hands a new rule over, and IptcHelper::appendRule() holds it until
   libiptc has copied it.
*/
using IptEntryPtr = std::unique_ptr<ipt_entry, decltype(&std::free)>;

#endif
