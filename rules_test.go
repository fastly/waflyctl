package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRuleHeadPageData(t *testing.T) {
	tsvr := APIHarness{}
	p, err := tsvr.Start()
	if err != nil {
		t.Fatalf("Error starting API test server. %s", err)
	}

	apiep := fmt.Sprintf("http://localhost:%d", p)
	defer tsvr.Stop()

	tests := []struct {
		testid          string
		serviceid       string
		wafid           string
		expPageLen      int
		expMetaTotal    int
		expMetaNumPages int
		expFirstRuleID  string
	}{
		{
			"Test 001",
			"[REDACTED-SID]",
			"[REDACTED-WAFID]",
			3,
			8,
			3,
			"2200002",
		},
	}

	for _, tt := range tests {
		t.Run(tt.testid, func(t *testing.T) {

			rl, err := getRuleHeadPageData(apiep, testAPIKey, tt.serviceid, tt.wafid)
			if err != nil {
				t.Errorf("Unexpected error '%s'", err)
			}

			assert.Equal(t, tt.expPageLen, len(rl.Data), "Number of rules does not match.")
			assert.Equal(t, tt.expMetaTotal, rl.Meta.RecordCount, "Total number of rules does not match.")
			assert.Equal(t, tt.expMetaNumPages, rl.Meta.TotalPages, "Total number of pages does not match.")
			assert.Equal(t, tt.expFirstRuleID, rl.Data[0].Attributes.ModsecRuleID, "First rule ID does not match.")

		})
	}
}

func TestGetRulePagedData(t *testing.T) {
	tsvr := APIHarness{}
	p, err := tsvr.Start()
	if err != nil {
		t.Fatalf("Error starting API test server. %s", err)
	}

	apiep := fmt.Sprintf("http://localhost:%d", p)
	defer tsvr.Stop()

	tests := []struct {
		testid         string
		serviceid      string
		wafid          string
		expPerPage     int
		expPageNo      int
		expPageLen     int
		expFirstRuleID string
	}{
		{
			"2nd Page",
			"[REDACTED-SID]",
			"[REDACTED-WAFID]",
			3,
			2,
			3,
			"2077878",
		},
		{
			"3rd Page",
			"[REDACTED-SID]",
			"[REDACTED-WAFID]",
			3,
			3,
			2,
			"2016874",
		},
	}

	for _, tt := range tests {
		t.Run(tt.testid, func(t *testing.T) {

			rl, err := getRulePagedData(apiep, testAPIKey, tt.serviceid, tt.wafid, tt.expPerPage, tt.expPageNo)
			if err != nil {
				t.Errorf("Unexpected error '%s'", err)
			}

			assert.Equal(t, tt.expPerPage, rl.Meta.PerPage, "Total number of rules per page does not match.")
			assert.Equal(t, tt.expPageNo, rl.Meta.CurrentPage, "Current Page does not match.")
			assert.Equal(t, tt.expPageLen, len(rl.Data), "Number of rules does not match.")
			assert.Equal(t, tt.expFirstRuleID, rl.Data[0].Attributes.ModsecRuleID, "First rule ID does not match.")

		})
	}

}

func TestGetRules(t *testing.T) {
	tsvr := APIHarness{}
	p, err := tsvr.Start()
	if err != nil {
		t.Fatalf("Error starting API test server. %s", err)
	}

	apiep := fmt.Sprintf("http://localhost:%d", p)
	defer tsvr.Stop()

	tests := []struct {
		testid             string
		serviceid          string
		wafid              string
		expLogRuleIDs      []string
		expBlockRuleIDs    []string
		expDisabledRuleIDs []string
	}{
		{
			"Test 001",
			"[REDACTED-SID]",
			"[REDACTED-WAFID]",
			[]string{"2200002", "2077878", "2077876", "2081321", "2025198"},
			[]string{"2084113", "2200000"},
			[]string{"2016874"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.testid, func(t *testing.T) {

			rl, rb, rd, err := GetRules(apiep, testAPIKey, tt.serviceid, tt.wafid)
			if err != nil {
				t.Errorf("Unexpected error '%s'", err)
			}

			checkRules(t, tt.expLogRuleIDs, rl, "Log")
			checkRules(t, tt.expBlockRuleIDs, rb, "Block")
			checkRules(t, tt.expDisabledRuleIDs, rd, "Disabled")
		})
	}
}

func checkRules(t *testing.T, exp []string, act []Rule, text string) {
	var ar []string
	for _, r := range act {
		ar = append(ar, r.Attributes.ModsecRuleID)
	}
	checkRulesStringArr(t, exp, ar, text)
}

func checkRulesStringArr(t *testing.T, exp []string, act []string, text string) {
	assert.Equal(t, len(exp), len(act), fmt.Sprintf("Number of %s rules.", text))
	for _, er := range exp {
		var f bool
		for _, ar := range act {
			if er == ar {
				f = true
				break
			}
		}
		assert.Equal(t, true, f, fmt.Sprintf("Rule %s not found in %s rules.", er, text))
	}
}

func rulesToString(r []Rule) string {
	var rs string
	rsa := ruleArrToSortedStringArr(r)
	for _, r := range rsa {
		rs += r + ", "
	}
	return strings.TrimSuffix(rs, ", ")
}
