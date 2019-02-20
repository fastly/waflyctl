package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetBackupData(t *testing.T) {
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
		expOWASP           OWASPSettings
	}{
		{
			"Simple Test",
			"[REDACTED-SID]",
			"[REDACTED-WAFID]",
			[]string{"2200002", "2077878", "2077876", "2081321", "2025198"},
			[]string{"2084113", "2200000"},
			[]string{"2016874"},
			OWASPSettings{
				ID:                            "4HWq26YF12xqZytqTy3LPa",
				AllowedHTTPVersions:           "HTTP/1.0 HTTP/1.1 HTTP/2",
				AllowedMethods:                "GET HEAD POST OPTIONS PUT PATCH DELETE",
				AllowedRequestContentType:     "application/x-www-form-urlencoded|multipart/form-data|text/xml|application/xml|application/x-amf|application/json|text/plain",
				ArgLength:                     800,
				ArgNameLength:                 800,
				CombinedFileSizes:             10000000,
				CreatedAt:                     "2017-01-01T01:01:01Z",
				CriticalAnomalyScore:          5,
				CRSValidateUTF8Encoding:       false,
				ErrorAnomalyScore:             4,
				HighRiskCountryCodes:          "",
				HTTPViolationScoreThreshold:   5,
				InboundAnomalyScoreThreshold:  10,
				LFIScoreThreshold:             5,
				MaxFileSize:                   10000000,
				MaxNumArgs:                    255,
				NoticeAnomalyScore:            2,
				ParanoiaLevel:                 3,
				PHPInjectionScoreThreshold:    5,
				RCEScoreThreshold:             5,
				RestrictedExtensions:          ".asa/ .asax/ .ascx/ .axd/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ .conf/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .ini/ .key/ .licx/ .lnk/ .log/ .mdb/ .old/ .pass/ .pdb/ .pol/ .printer/ .pwd/ .resources/ .resx/ .sql/ .sys/ .vb/ .vbs/ .vbproj/ .vsdisco/ .webinfo/ .xsd/ .xsx",
				RestrictedHeaders:             "/proxy/ /lock-token/ /content-range/ /translate/ /if/",
				RFIScoreThreshold:             5,
				SessionFixationScoreThreshold: 5,
				SQLInjectionScoreThreshold:    5,
				TotalArgLength:                6400,
				UpdatedAt:                     "2018-01-01T01:01:01Z",
				WarningAnomalyScore:           3,
				XSSScoreThreshold:             5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.testid, func(t *testing.T) {

			b, err := getBackupData(apiep, testAPIKey, tt.serviceid, tt.wafid)
			if err != nil {
				t.Errorf("Unexpected error '%s'", err)
			}

			assert.Equal(t, tt.serviceid, b.ServiceID, "Service ID does not match.")
			assert.Equal(t, tt.wafid, b.WAFID, "WAF ID does not match.")

			checkRulesStringArr(t, tt.expLogRuleIDs, b.Log, "Log")
			checkRulesStringArr(t, tt.expBlockRuleIDs, b.Block, "Block")
			checkRulesStringArr(t, tt.expDisabledRuleIDs, b.Disabled, "Disabled")

			if assert.NotNil(t, b.Owasp, "OWASP is nil.") {
				assert.Equal(t, tt.expOWASP, b.Owasp, "OWASP attributes do not match.")
			}

		})
	}
}
