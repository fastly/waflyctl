package main

import (
	"bytes"
	"fmt"

	"github.com/google/jsonapi"
	resty "gopkg.in/resty.v1"
)

// OWASPSettings defines a type intended for serialized TOML output as part of
// backups & Configuration
// TODO: This includes extra fields which are relevant to backup, but not neccessarily
// relevant (perhaps even break) the OWASP update / provision. Test this! Perhaps use sethvargo's library for this.
type OWASPSettings struct {
	ID                               string `jsonapi:"primary,owasp"`
	AllowedHTTPVersions              string `jsonapi:"attr,allowed_http_versions"`
	AllowedMethods                   string `jsonapi:"attr,allowed_methods"`
	AllowedRequestContentType        string `jsonapi:"attr,allowed_request_content_type"`
	AllowedRequestContentTypeCharset string `jsonapi:"attr,allowed_request_content_type_charset"`
	ArgLength                        int    `jsonapi:"attr,arg_length"`
	ArgNameLength                    int    `jsonapi:"attr,arg_name_length"`
	CombinedFileSizes                int    `jsonapi:"attr,combined_file_sizes"`
	CreatedAt                        string `jsonapi:"attr,created_at"`
	CriticalAnomalyScore             int    `jsonapi:"attr,critical_anomaly_score"`
	CRSValidateUTF8Encoding          bool   `jsonapi:"attr,crs_validate_utf8_encoding"`
	ErrorAnomalyScore                int    `jsonapi:"attr,error_anomaly_score"`
	HighRiskCountryCodes             string `jsonapi:"attr,high_risk_country_codes"`
	HTTPViolationScoreThreshold      int    `jsonapi:"attr,http_violation_score_threshold"`
	InboundAnomalyScoreThreshold     int    `jsonapi:"attr,inbound_anomaly_score_threshold"`
	LFIScoreThreshold                int    `jsonapi:"attr,lfi_score_threshold"`
	MaxFileSize                      int    `jsonapi:"attr,max_file_size"`
	MaxNumArgs                       int    `jsonapi:"attr,max_num_args"`
	NoticeAnomalyScore               int    `jsonapi:"attr,notice_anomaly_score"`
	ParanoiaLevel                    int    `jsonapi:"attr,paranoia_level"`
	PHPInjectionScoreThreshold       int    `jsonapi:"attr,php_injection_score_threshold"`
	RCEScoreThreshold                int    `jsonapi:"attr,rce_score_threshold"`
	RestrictedExtensions             string `jsonapi:"attr,restricted_extensions"`
	RestrictedHeaders                string `jsonapi:"attr,restricted_headers"`
	RFIScoreThreshold                int    `jsonapi:"attr,rfi_score_threshold"`
	SessionFixationScoreThreshold    int    `jsonapi:"attr,session_fixation_score_threshold"`
	SQLInjectionScoreThreshold       int    `jsonapi:"attr,sql_injection_score_threshold"`
	TotalArgLength                   int    `jsonapi:"attr,total_arg_length"`
	UpdatedAt                        string `jsonapi:"attr,updated_at"`
	WarningAnomalyScore              int    `jsonapi:"attr,warning_anomaly_score"`
	XSSScoreThreshold                int    `jsonapi:"attr,xss_score_threshold"`
}

// GetOWASPSettings pulls OWASP setting data from the API.
// Specifying endpoint, api key, service ID, WAF ID.
func GetOWASPSettings(apiep string, apikey string, sid string, wid string) (*OWASPSettings, error) {
	ow := OWASPSettings{}

	apiCall := fmt.Sprintf("%s/service/%s/wafs/%s/owasp", apiep, sid, wid)

	resp, err := resty.R().
		SetHeader("Accept", "application/vnd.api+json").
		SetHeader("Fastly-Key", apikey).
		SetHeader("Content-Type", "application/vnd.api+json").
		Get(apiCall)

	if err != nil {
		return &ow, fmt.Errorf("Error while making API call to %s", apiCall)
	}

	// check status
	if resp.StatusCode() != 200 {
		return &ow, fmt.Errorf("Non 200 response while making API call to %s", apiCall)
	}

	// unmarshal the response
	err = jsonapi.UnmarshalPayload(bytes.NewReader(resp.Body()), &ow)
	if err != nil {
		return &ow, fmt.Errorf("Error while parsing API response from %s", apiCall)
	}

	return &ow, nil
}
