package util

import (
	"sort"
	"testing"
)

func TestWithInts(t *testing.T) {
	v := []int{100, 101, 99, 98, 102}
	Sort(len(v),
		func(i, j int) bool {
			return v[i] < v[j]
		},
		func(i, j int) {
			v[i], v[j] = v[j], v[i]
		})

	if !sort.IntsAreSorted(v) {
		t.Errorf("%v not sorted.", v)
	}
}

func TestEmpty(t *testing.T) {
	Sort(0,
		func(i, j int) bool {
			return false
		},
		func(i, j int) {
		})
}
