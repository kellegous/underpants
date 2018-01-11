package util

import (
	"sort"
)

type sorter struct {
	n    int
	less func(i, j int) bool
	swap func(i, j int)
}

func (s *sorter) Less(i, j int) bool {
	return s.less(i, j)
}
func (s *sorter) Swap(i, j int) {
	s.swap(i, j)
}

func (s *sorter) Len() int {
	return s.n
}

// Sort provides a generic way to sort things without having to create
// new types or adorn existing types with sort functions.
func Sort(n int, less func(i, j int) bool, swap func(i, j int)) {
	sort.Sort(&sorter{
		n:    n,
		less: less,
		swap: swap,
	})
}
