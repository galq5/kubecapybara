package agent

import (
	"reflect"
	"testing"
)

func TestParseCPUList(t *testing.T) {
	for in, want := range map[string][]int{
		"0-3\n":     {0, 1, 2, 3},
		"0,2-3,8":   {0, 2, 3, 8},
		"5":         {5},
		"0-1,4-5\n": {0, 1, 4, 5},
		"garbage":   nil,
		"3-1":       nil,
		"":          nil,
	} {
		if got := parseCPUList(in); !reflect.DeepEqual(got, want) {
			t.Errorf("parseCPUList(%q) = %v, want %v", in, got, want)
		}
	}
	if len(onlineCPUs()) == 0 {
		t.Fatal("no online CPUs")
	}
}
