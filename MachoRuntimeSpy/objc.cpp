#include "objc.hpp"

namespace objc {
  class_rw_t *get_objc_class_data_addr(uintptr_t bits) {
    return (struct class_rw_t * )(bits & FAST_DATA_MASK);
  }
  bool hasArray(x_array_t *t) { return t->arrayAndFlag & 1; }

  array_t *array(x_array_t *t) { return (array_t *) (t->arrayAndFlag & ~1); }

  List **arrayList(x_array_t *t) {
    if (hasArray(t)) {
      return array(t)->lists;
    } else {
      return &(t->list);
    }
  }
}