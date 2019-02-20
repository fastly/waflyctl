package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var (
	rsRules = regexp.MustCompile(`^/service/([^/]+)/wafs/([^/]+)/rule_statuses$`)
	rsOWASP = regexp.MustCompile(`^/service/([^/]+)/wafs/([^/]+)/owasp$`)
)

// APIHarness encapsulates http.Server and provides functions specific to the
// Fastly API test harness.
type APIHarness struct {
	Listener net.Listener
}

// Start opens a listener on the next available port on the local system
func (h *APIHarness) Start() (int, error) {
	var err error
	h.Listener, err = net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	p := h.Listener.Addr().(*net.TCPAddr).Port
	fmt.Printf("Started test server on port: %v\n", p)
	go http.Serve(h.Listener, h)

	return p, nil
}

// Stop closes the listener
func (h *APIHarness) Stop() {
	// just closing the listener isn't very graceful, but it doesn't need to be,
	// it is accessed by only the tests, and Stop() is only invoked after tests
	// have completed.
	err := h.Listener.Close()

	if err != nil {
		fmt.Printf("Error stopping test server. %s\n", err)
	}

	fmt.Printf("Stopped test server\n")
}

// TODO: This whole handler things is rubbish, think of a better way to do it
func (h *APIHarness) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	fmt.Printf("Test Server: received path: %s\n", getFullPath(r.URL.Path, r.URL.RawQuery))
	switch {

	// Handle OWASP Settings
	case rsOWASP.MatchString(r.URL.Path):

		// load owasp settings from file
		ow, err := loadOWASPSettings()
		if err != nil {
			returnError(w, r, errors.New("error loading OWASP settings"))
		}

		//build the response object
		js, err := json.Marshal(ow)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		fmt.Fprintf(w, "%s", js)

	// Handle Rules
	case rsRules.MatchString(r.URL.Path):
		res := rsRules.FindAllStringSubmatch(r.URL.Path, -1)
		wid := res[0][2]

		// load test rules from file
		rs, err := loadRules()
		if err != nil {
			returnError(w, r, errors.New("error loading rules"))
		}

		// capture page numbers & size
		pn, ps := 1, 3
		if pss, ok := r.URL.Query()["page[size]"]; ok {
			i, err := strconv.Atoi(pss[0])
			if err == nil {
				ps = i
			}
		}
		if pns, ok := r.URL.Query()["page[number]"]; ok {
			i, err := strconv.Atoi(pns[0])
			if err == nil {
				pn = i
			}
		}

		// build the new rule list
		var rl RuleList
		rl.Data = extractRules(rs, pn, ps)
		rl.Meta.CurrentPage = pn
		rl.Meta.PerPage = ps
		rl.Meta.RecordCount = len(rs)
		rl.Meta.TotalPages = int(math.Ceil(float64(len(rs)) / float64(ps)))

		// build the response object
		js, err := json.Marshal(rl)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// substitute tokens
		jss := strings.Replace(string(js), "{{waf-id}}", wid, -1)

		// write to response stream
		w.Header().Set("Content-Type", "application/vnd.api+json")
		fmt.Fprintf(w, "%s", []byte(jss))

	default:
		w.WriteHeader(http.StatusNotFound)
	}

}

func extractRules(ir []Rule, pn int, ps int) []Rule {
	// extract start
	st := (pn - 1) * ps
	if len(ir) < ps {
		return ir
	}
	ir = ir[st:]

	// check length & trim
	if len(ir) > ps {
		return ir[0:ps]
	}
	return ir

}

func loadRules() ([]Rule, error) {
	var rs []Rule
	rp := "apitestdata/rules.json"
	b, err := ioutil.ReadFile(rp)
	if err != nil {
		return rs, fmt.Errorf("error reading rules file. %s", err)
	}

	err = json.Unmarshal(b, &rs)
	if err != nil {
		return rs, fmt.Errorf("error unmarshalling rules. %s", err)
	}

	return rs, nil
}

func loadOWASPSettings() (interface{}, error) {
	var ow interface{}
	rp := "apitestdata/owasp.json"
	b, err := ioutil.ReadFile(rp)
	if err != nil {
		return ow, fmt.Errorf("error reading OWASP settings file. %s", err)
	}

	err = json.Unmarshal(b, &ow)
	if err != nil {
		return ow, fmt.Errorf("error unmarshalling OWASP settings. %s", err)
	}

	return ow, nil
}

func getFullPath(p, q string) string {
	if len(q) == 0 {
		return p
	}
	return fmt.Sprintf("%s?%s", p, q)
}

func returnError(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusBadRequest)
}
