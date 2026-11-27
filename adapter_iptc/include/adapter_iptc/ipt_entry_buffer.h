#ifndef IPT_ENTRY_BUFFER_H
#define IPT_ENTRY_BUFFER_H

#include <libiptc/libiptc.h>
#include <vector>

/* LEARN: an ipt_entry is a variable-length buffer (header, matches, target), so it is held as a
   vector of ipt_entry big enough to cover it: the elements are only storage, and the rule is read
   and written through the first one and its elems. A vector of the type itself gives the right
   alignment, a zeroed buffer and the release of the memory, with no malloc, no C array and no
   cast. Whoever holds an IptEntryBuffer owns the rule: RuleMapper::toEntry() hands a new rule
   over, and IptcHelper::appendRule() holds it until libiptc has copied it.
   Only element 0 is an ipt_entry; the matches and the target spill into the elements after it and
   are reached by offset, so the buffer is passed whole (data()), never element by element.
   Why that is acceptable: docs/adapter-iptc-rule-mapper.md.
*/
using IptEntryBuffer = std::vector<ipt_entry>;

#endif
