package main

import (
	"testing"
)

func TestExtractRules(t *testing.T) {

	tests := []struct {
		testid     string
		rules      []Rule
		pagenumber int
		pagesize   int
		expected   []Rule
	}{
		{
			"Extract Page 1 of Size 1",
			[]Rule{{ID: "001"}, {ID: "002"}, {ID: "003"}, {ID: "004"}, {ID: "005"}, {ID: "006"}, {ID: "007"}, {ID: "008"}},
			1,
			1,
			[]Rule{{ID: "001"}},
		},
		{
			"Extract Page 1 of Size 3",
			[]Rule{{ID: "001"}, {ID: "002"}, {ID: "003"}, {ID: "004"}, {ID: "005"}, {ID: "006"}, {ID: "007"}, {ID: "008"}},
			1,
			3,
			[]Rule{{ID: "001"}, {ID: "002"}, {ID: "003"}},
		},
		{
			"Extract Page Larger than Input",
			[]Rule{{ID: "001"}, {ID: "002"}},
			1,
			3,
			[]Rule{{ID: "001"}, {ID: "002"}},
		},
		{
			"Extract Page 2 of Size 3",
			[]Rule{{ID: "001"}, {ID: "002"}, {ID: "003"}, {ID: "004"}, {ID: "005"}, {ID: "006"}, {ID: "007"}, {ID: "008"}},
			2,
			3,
			[]Rule{{ID: "004"}, {ID: "005"}, {ID: "006"}},
		},
		{
			"Extract Page 3 of Size 3",
			[]Rule{{ID: "001"}, {ID: "002"}, {ID: "003"}, {ID: "004"}, {ID: "005"}, {ID: "006"}, {ID: "007"}, {ID: "008"}},
			3,
			3,
			[]Rule{{ID: "007"}, {ID: "008"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.testid, func(t *testing.T) {

			actual := extractRules(tt.rules, tt.pagenumber, tt.pagesize)

			if !RulesEqual(actual, tt.expected) {
				t.Errorf("Unexpected output, expected (len:%d): %v, actual (len%d) %v", len(tt.expected), tt.expected, len(actual), actual)
			}

		})
	}

}

func RulesEqual(a, b []Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v.ID != b[i].ID {
			return false
		}
	}
	return true
}
