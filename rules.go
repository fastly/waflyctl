package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	resty "gopkg.in/resty.v1"
)

// GetRules pulls all rule data from the API.
// Specifying endpoint, api key, service ID, WAF ID.
// This method pulls first head page which contains metadata describing subsequent
// pages and then pulls the subsequent pages.
// Returned Log Rules, Block Rules, Disabled Rules and any Error.
// Note: Rules are ordered based on when the async responses were processed.
func GetRules(apiep, apikey, sid, wid string) ([]Rule, []Rule, []Rule, error) {
	rl, rb, rd := []Rule{}, []Rule{}, []Rule{}
	// pull the head page & read the meta for following pages
	rf, err := getRuleHeadPageData(apiep, apikey, sid, wid)
	if err != nil {
		return rl, rb, rd, fmt.Errorf("error pulling first page of rules. %s", err)
	}

	// process the results of the first page
	for _, r := range rf.Data {
		switch r.Attributes.Status {
		case "log":
			rl = append(rl, r)
		case "block":
			rb = append(rb, r)
		case "disabled":
			rd = append(rd, r)
		}
	}

	in := make(chan inGetRulePagedData)
	out := make(chan outGetRulePagedData)

	// for joining the async calls for the paged rule data
	var wgGetRules sync.WaitGroup

	// create a pool of workers for pulling paged data
	for i := 0; i < 10; i++ {
		go getRulePagedDataAsync(in, out)
	}

	// process data from responses on the output channel
	var rerr error
	go func() {
		for r := range out {
			if r.err != nil {
				rerr = fmt.Errorf("error(s) pulling pages of rules. %s", r.err)
			}

			for _, r := range r.rl.Data {
				switch r.Attributes.Status {
				case "log":
					rl = append(rl, r)
				case "block":
					rb = append(rb, r)
				case "disabled":
					rd = append(rd, r)
				}
			}
			wgGetRules.Done()
		}
	}()

	// invoke requests for paged data async
	for i := 2; i <= rf.Meta.TotalPages; i++ {
		wgGetRules.Add(1)
		in <- inGetRulePagedData{apiep, apikey, sid, wid, rf.Meta.PerPage, i}
	}

	// close input channel since no more jobs are being sent to input channel
	close(in)

	// wait for all responses to be processed
	wgGetRules.Wait()

	// close output channel since all workers have finished processing
	close(out)

	// check for error
	if rerr != nil {
		return rl, rb, rd, rerr
	}

	return rl, rb, rd, nil
}

// getRuleHeadPageData pulls the first page of data from the API.
// Specifying endpoint, api key, service ID, WAF ID.
// This method returns metadata regarding the total size of the dataset allowing
// retrieval of subsequent pages.
func getRuleHeadPageData(apiep string, apikey string, sid string, wid string) (RuleList, error) {
	return getRulePagedData(apiep, apikey, sid, wid, -1, -1)
}

// getRulePagedData pulls paged data from the API.
// Specifying endpoint, api key, service ID, WAF ID, records per page and page number.
func getRulePagedData(apiep string, apikey string, sid string, wid string, pp int, pn int) (RuleList, error) {
	rl := RuleList{}

	apiCall := fmt.Sprintf("%s/service/%s/wafs/%s/rule_statuses", apiep, sid, wid)
	if pp != -1 && pn != -1 {
		apiCall += fmt.Sprintf("?page[number]=%d&page[size]=%d", pn, pp)
	}

	resp, err := resty.R().
		SetHeader("Accept", "application/vnd.api+json").
		SetHeader("Fastly-Key", apikey).
		SetHeader("Content-Type", "application/vnd.api+json").
		Get(apiCall)

	if err != nil {
		return rl, fmt.Errorf("Error while making API call to %s", apiCall)
	}

	// check status
	if resp.StatusCode() != 200 {
		return rl, fmt.Errorf("Non 200 response while making API call to %s", apiCall)
	}

	// unmarshal the response
	err = json.Unmarshal(resp.Body(), &rl)
	if err != nil {
		return rl, fmt.Errorf("Error while parsing API response from %s", apiCall)
	}

	return rl, nil
}

// inGetRulePagedData defines the input parameters for getRulePagedData so data
// can be sent down a channel
type inGetRulePagedData struct {
	apiep  string
	apikey string
	sid    string
	wid    string
	pp     int
	pn     int
}

// outGetRulePagedData defines output parameters for getRulePagedData so the
// response can be sent up the output channel
type outGetRulePagedData struct {
	rl  RuleList
	err error
}

// getRulePagedDataAsync provides input/output channels for async execution of
// getRulePagedData. Because it wraps getRulePagedData, it allows it to be testable.
func getRulePagedDataAsync(in chan inGetRulePagedData, out chan outGetRulePagedData) {
	for v := range in {
		rn, err := getRulePagedData(v.apiep, v.apikey, v.sid, v.wid, v.pp, v.pn)
		out <- outGetRulePagedData{rn, err}
	}
}

// ruleArrToSortedStringArr translates a slice of Rule into a slice of string,
// identifying the rule by it's ModsecRuleID
func ruleArrToSortedStringArr(rl []Rule) []string {
	var ret []string
	for _, r := range rl {
		ret = append(ret, r.Attributes.ModsecRuleID)
	}
	sort.Strings(ret)

	return ret
}
