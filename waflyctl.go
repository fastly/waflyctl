/*
WAF provisioning tool
Author: @Enrique (enrique@fastly.com)
*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/sethvargo/go-fastly/fastly"
	"gopkg.in/resty.v1"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"os/user"
)

var (
	//logging variables
	logFile string

	//Trace level logging NOT USED
	Trace *log.Logger

	//Info level logging
	Info *log.Logger

	//Warning level logging
	Warning *log.Logger

	//Error level logging
	Error *log.Logger

	// version number
	version = "dev"
	date    = "unknown"

	//HOMEDIRECTORY static variable
	HOMEDIRECTORY string

)



// TOMLConfig is the applications config file
type TOMLConfig struct {
	Logpath       string
	APIEndpoint   string
	Tags          []string
	Action        string
	Rules         []int64
	DisabledRules []int64
	Owasp         owaspSettings
	Weblog        WeblogSettings
	Waflog        WaflogSettings
	Vclsnippet    VCLSnippetSettings
	Response      ResponseSettings
	Prefetch      PrefetchSettings
}

type owaspSettings struct {
	AllowedHTTPVersions           string
	AllowedMethods                string
	AllowedRequestContentType     string
	ArgLength                     int
	ArgNameLength                 int
	CombinedFileSizes             int
	CriticalAnomalyScore          int
	CRSValidateUTF8Encoding       bool
	ErrorAnomalyScore             int
	HTTPViolationScoreThreshold   int
	InboundAnomalyScoreThreshold  int
	LFIScoreThreshold             int
	MaxFileSize                   int
	MaxNumArgs                    int
	NoticeAnomalyScore            int
	ParanoiaLevel                 int
	PHPInjectionScoreThreshold    int
	RCEScoreThreshold             int
	RestrictedExtensions          string
	RestrictedHeaders             string
	RFIScoreThreshold             int
	SessionFixationScoreThreshold int
	SQLInjectionScoreThreshold    int
	XSSScoreThreshold             int
	TotalArgLength                int
	WarningAnomalyScore           int
}

// WeblogSettings parameters for logs in config file
type WeblogSettings struct {
	Name        string
	Address     string
	Port        uint
	Tlscacert   string
	Tlshostname string
	Format      string
}

// VCLSnippetSettings parameters for snippets in config file
type VCLSnippetSettings struct {
	Name     string
	Content  string
	Type     string
	Priority int
	Dynamic  int
}

// Version information from Fastly API
type Version struct {
	PublishKey string `json:"publish_key"`
	Name       string `json:"name"`
	Versions   []struct {
		Testing   bool        `json:"testing"`
		Locked    bool        `json:"locked"`
		Number    int         `json:"number"`
		Active    bool        `json:"active"`
		ServiceID string      `json:"service_id"`
		Staging   bool        `json:"staging"`
		CreatedAt time.Time   `json:"created_at"`
		DeletedAt interface{} `json:"deleted_at"`
		Comment   string      `json:"comment"`
		UpdatedAt time.Time   `json:"updated_at"`
		Deployed  bool        `json:"deployed"`
	} `json:"versions"`
	DeletedAt  interface{} `json:"deleted_at"`
	CreatedAt  time.Time   `json:"created_at"`
	Comment    string      `json:"comment"`
	CustomerID string      `json:"customer_id"`
	UpdatedAt  time.Time   `json:"updated_at"`
	ID         string      `json:"id"`
}

// WaflogSettings parameters from config
type WaflogSettings struct {
	Name        string
	Address     string
	Port        uint
	Tlscacert   string
	Tlshostname string
	Format      string
}

// ResponseSettings parameters from config
type ResponseSettings struct {
	Name           string
	HTTPStatusCode uint
	HTTPResponse   string
	ContentType    string
	Content        string
}

// PrefetchSettings parameters from config
type PrefetchSettings struct {
	Name      string
	Statement string
	Type      string
	Priority  int
}

// Service information from Fastly API
type Service struct {
	DomainName    string `json:"domain_name"`
	ServiceID     string `json:"service_id"`
	ActiveVersion int    `json:"active_version"`
}

// Features from Fastly API
type Features struct {
	Features []string `json:"features"`
}

// RuleList contains list of rules
type RuleList struct {
	Data  []Rule
	Links struct {
		Last  string `json:"last"`
		First string `json:"first"`
		Next  string `json:"next"`
	} `json:"links"`

	Meta struct {
		CurrentPage int `json:"current_page"`
		PerPage     int `json:"per_page"`
		RecordCount int `json:"record_count"`
		TotalPages  int `json:"total_pages"`
	} `json:"meta"`
}

// Rule from Fastly API
type Rule struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Message       string      `json:"message"`
		Status        string      `json:"status"`
		Origin        string      `json:"origin"`
		ParanoiaLevel int         `json:"paranoia_level"`
		Revision      string      `json:"revision"`
		Severity      int         `json:"severity"`
		Version       interface{} `json:"version"`
		RuleID        string      `json:"rule_id"`
		ModsecRuleID  string      `json:"modsec_rule_id"`
		UniqueRuleID  string      `json:"unique_rule_id"`
		Source        interface{} `json:"source"`
		Vcl           interface{} `json:"vcl"`
	} `json:"attributes"`
}

// Snippet from Fastly API
type Snippet []struct {
	ID        string      `json:"id"`
	ServiceID string      `json:"service_id"`
	Version   string      `json:"version"`
	Name      string      `json:"name"`
	Priority  string      `json:"priority"`
	Dynamic   string      `json:"dynamic"`
	Type      string      `json:"type"`
	Content   interface{} `json:"content"`
}

// PagesOfRules contains a list of rulelist
type PagesOfRules struct {
	page []RuleList
}

// PagesOfConfigurationSets contains a list of ConfigSetList
type PagesOfConfigurationSets struct {
	page []ConfigSetList
}

// ConfigSetList contains a list of configuration set and its metadata
type ConfigSetList struct {
	Data  []ConfigSet
	Links struct {
		Last  string `json:"last"`
		First string `json:"first"`
		Next  string `json:"next"`
	} `json:"links"`
	Meta struct {
		CurrentPage int `json:"current_page"`
		PerPage     int `json:"per_page"`
		RecordCount int `json:"record_count"`
		TotalPages  int `json:"total_pages"`
	} `json:"meta"`
}

// ConfigSet defines details of a configuration set
type ConfigSet struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Active bool      `json:"active"`
		Name   string `json:"name"`
	} `json:"attributes"`
}

//Init function starts our logger
func Init(configFile string) TOMLConfig {

	//load configs
	var config TOMLConfig
	if _, err := toml.DecodeFile(configFile, &config); err != nil {
		fmt.Println("Could not read config file -", err)
		os.Exit(1)
	}

	//assigned the right log path
	if config.Logpath == "" {
		fmt.Println("no log path defined using default waflyctl.log")
		config.Logpath = "waflyctl.log"
	}
	/*
		fmt.Println("config settings: ")
		fmt.Println("- logpath",config.Logpath)
		fmt.Println("- apiendpoint", config.APIEndpoint)
		fmt.Println("- owasp", config.Owasp)
		fmt.Println("- weblogs", config.Weblog.Port)
		fmt.Println("- waflogs", config.Waflog.Port)
	*/
	//now lets create a logging object
	file, err := os.OpenFile(config.Logpath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalln("Failed to open log file", logFile, ":", err)
	}

	multi := io.MultiWriter(file, os.Stdout)

	Info = log.New(multi,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Warning = log.New(multi,
		"WARNING: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(multi,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	return config
}

func getActiveVersion(client fastly.Client, serviceID, apiKey string, config TOMLConfig) int {

	var activeVersion int

	//get version list
	apiCall := config.APIEndpoint + "/service/" + serviceID
	resp, err := resty.R().
		SetHeader("Accept", "application/vnd.api+json").
		SetHeader("Fastly-Key", apiKey).
		Get(apiCall)

	//check if we had an issue with our call
	if err != nil {
		Error.Println("Error with API call: " + apiCall)
		os.Exit(1)
	}

	//unmarshal the response and extract the version list from response
	body := Version{}
	json.Unmarshal([]byte(resp.String()), &body)

	//find the active version
	for _, version := range body.Versions {
		if version.Active == true {
			activeVersion = version.Number
			return activeVersion
		}
	}

	// return false if no active version is found
	Error.Println("Found no active version on the service, service ID might be incorrect..exiting")
	os.Exit(1)
	return 0
}
func cloneVersion(client fastly.Client, serviceID, apiKey string, config TOMLConfig, activeVersion int) (bool, int) {

	Info.Printf("cloning current service version #%v", activeVersion)
	version, err := client.CloneVersion(&fastly.CloneVersionInput{
		Service: serviceID,
		Version: activeVersion,
	})
	if err != nil {
		Error.Println(err)
		Error.Printf("Error Cloning Service %s", serviceID)
		os.Exit(1)
		return false, 0
	}

	Info.Printf("new working service version #%v", version.Number)
	return true, version.Number

}

func prefetchCondition(client fastly.Client, serviceID string, version int, config TOMLConfig) bool {

	conditions, err := client.ListConditions(&fastly.ListConditionsInput{
		Service: serviceID,
		Version: version,
	})

	if err != nil {
		Error.Fatal(err)
		return false
	}
	for _, condition := range conditions {
		//do we have a condition name waf_prefetch, if not create one
		//iterate through returned conditions check if any say waf_prefetch if not lets configure the service
		if strings.EqualFold(condition.Name, config.Prefetch.Name) {
			Error.Println("WAF Prefetch already exists with name: " + condition.Name + "..skipping creating conditions")
			return false
		}
	}
	_, err = client.CreateCondition(&fastly.CreateConditionInput{
		Service:   serviceID,
		Version:   version,
		Name:      config.Prefetch.Name,
		Statement: config.Prefetch.Statement,
		Type:      config.Prefetch.Type,
		Priority:  10,
	})

	if err != nil {
		Error.Fatal(err)
		return false
	}

	return true
}

func responseObject(client fastly.Client, serviceID string, version int, config TOMLConfig) bool {
	responses, err := client.ListResponseObjects(&fastly.ListResponseObjectsInput{
		Service: serviceID,
		Version: version,
	})

	if err != nil {
		Error.Fatal(err)
		return false
	}
	for _, response := range responses {
		//iterate through returned responses check if any say WAF_Response if not lets configure the service
		Info.Println(response.Name)
		if strings.EqualFold(response.Name, config.Response.Name) {
			Error.Println("WAF Response already exists with name: " + response.Name + "..skipping creating Response Object")
			return false
		}
	}
	_, err = client.CreateResponseObject(&fastly.CreateResponseObjectInput{
		Service:     serviceID,
		Version:     version,
		Name:        config.Response.Name,
		Status:      config.Response.HTTPStatusCode,
		Response:    config.Response.HTTPResponse,
		Content:     config.Response.Content,
		ContentType: config.Response.ContentType,
	})
	if err != nil {
		Error.Fatal(err)
		return false
	}
	return true
}

//func rulesConfig(apiEndpoint, apiKey, serviceID, wafID string, client fastly.Client, config tomlConfig)
func vclSnippet(serviceID, apiKey string, version int, config TOMLConfig) bool {
	//Work on Tags first
	//API Endpoint to call for domain searches
	//strconv.FormatInt(rule, 10)
	apiCall := config.APIEndpoint + "/service/" + serviceID + "/version/" + strconv.Itoa(version) + "/snippet"

	//get list of current snippets
	resp, err := resty.R().
		SetHeader("Accept", "application/vnd.api+json").
		SetHeader("Fastly-Key", apiKey).
		Get(apiCall)

	//check if we had an issue with our call
	if err != nil {
		Error.Println("Error with API call: " + apiCall)
		os.Exit(1)
	}

	//unmarshal the response and extract the service id
	body := Snippet{}
	json.Unmarshal([]byte(resp.String()), &body)

	//check if it has already been created
	for _, snippet := range body {
		if snippet.Name == config.Vclsnippet.Name {
			Warning.Println(config.Vclsnippet.Name + " already excists not creating a new one")
			return false
		}
	}

	//otherwise lets create one
	resp, err = resty.R().
		SetHeader("Accept", "application/json").
		SetHeader("Fastly-Key", apiKey).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBody(`name=` + config.Vclsnippet.Name + `&type=` + config.Vclsnippet.Type + `&priority=` + strconv.Itoa(config.Vclsnippet.Priority) + `&dynamic=` + strconv.Itoa(config.Vclsnippet.Dynamic) + `&content=` + config.Vclsnippet.Content).
		Post(apiCall)

	//check if we had an issue with our call
	if err != nil {
		Error.Println("Error with API call: " + apiCall)
		os.Exit(1)
	}

	if resp.Status() == "200 OK" {
		return true
	}

	Error.Println("Could not add dynamic VCL snippet Fastly_WAF_Snippet the response was: ", resp.String())
	return false

}

// FastlyLogging configures the logging endpoints for the customer
func FastlyLogging(client fastly.Client, serviceID string, version int, config TOMLConfig) bool {
	//add logging logic to service
	// create req logging endpoint
	_, err := client.CreateSyslog(&fastly.CreateSyslogInput{
		Service:       serviceID,
		Version:       version,
		Name:          config.Weblog.Name,
		Address:       config.Weblog.Address,
		Port:          config.Weblog.Port,
		UseTLS:        fastly.CBool(true),
		IPV4:          config.Weblog.Address,
		TLSCACert:     config.Weblog.Tlscacert,
		TLSHostname:   config.Weblog.Tlshostname,
		Format:        config.Weblog.Format,
		FormatVersion: 2,
		MessageType:   "blank",
	})
	if err != nil {
		fmt.Print(err)
		return false
	}
	Info.Println("Created request logging endpoint: " + config.Weblog.Name)

	// create waf logging endpoint
	_, err = client.CreateSyslog(&fastly.CreateSyslogInput{
		Service:       serviceID,
		Version:       version,
		Name:          config.Waflog.Name,
		Address:       config.Waflog.Address,
		Port:          config.Waflog.Port,
		UseTLS:        fastly.CBool(true),
		IPV4:          config.Waflog.Address,
		TLSCACert:     config.Waflog.Tlscacert,
		TLSHostname:   config.Waflog.Tlshostname,
		Format:        config.Waflog.Format,
		FormatVersion: 2,
		MessageType:   "blank",
		Placement:     "waf_debug",
	})
	if err != nil {
		fmt.Print(err)
		return false
	}
	Info.Println("Created WAF logging endpoint: " + config.Waflog.Name)
	return true
}

// FindCustomerID retrives a customerID using the Fastly API
func FindCustomerID(client fastly.Client, serviceID string) string {

	//have client return the service Info
	serviceInfo, err := client.GetService(&fastly.GetServiceInput{
		ID: serviceID,
	})
	if err != nil {
		Error.Printf("could not find a customer ID for service: %v", serviceID)
		os.Exit(1)

	}
	return serviceInfo.CustomerID
}

func checkWAF(apiKey, apiEndpoint string) bool {
	apiCall := apiEndpoint + "/verify"

	resp, err := resty.R().
		SetHeader("Accept", "application/vnd.api+json").
		SetHeader("Fastly-Key", apiKey).
		SetHeader("Content-Type", "application/vnd.api+json").
		Get(apiCall)

	if err != nil {
		Error.Fatal(err)
		return false
	}

	//unmarshal the response and extract the service id
	body := Features{}
	json.Unmarshal([]byte(resp.String()), &body)

	for _, feature := range body.Features {
		if feature == "waf" {
			Info.Printf("WAF Featured Enabled")
			return true
		}
	}
	Error.Printf("WAF Featured NOT Enabled on Account. Please contact Fastly at support@fastly.com")
	os.Exit(1)
	return false
}

func wafContainer(client fastly.Client, serviceID string, version int, config TOMLConfig) (bool, string) {
	waf, err := client.CreateWAF(&fastly.CreateWAFInput{
		Service:           serviceID,
		Version:           version,
		PrefetchCondition: config.Prefetch.Name,
		Response:          config.Response.Name,
	})
	if err != nil {
		Error.Fatal(err)
		return false, waf.ID
	}

	Info.Printf("WAF created with ID: %v", waf.ID)
	return true, waf.ID

}

func createOWASP(client fastly.Client, serviceID, wafID string, version int, config TOMLConfig) bool {
	//add tagging logic

	owasp, _ := client.GetOWASP(&fastly.GetOWASPInput{
		Service: serviceID,
		ID:      wafID,
	})

	if owasp.ID == "" {
		owasp, err := client.CreateOWASP(&fastly.CreateOWASPInput{
			Service: serviceID,
			ID:      wafID,
		})

		if err != nil {
			Error.Print(err)
			return false
		}

		owasp, err = client.UpdateOWASP(&fastly.UpdateOWASPInput{
			Service:                       serviceID,
			ID:                            wafID,
			OWASPID:                       owasp.ID,
			AllowedHTTPVersions:           config.Owasp.AllowedHTTPVersions,
			AllowedMethods:                config.Owasp.AllowedMethods,
			AllowedRequestContentType:     config.Owasp.AllowedRequestContentType,
			ArgLength:                     config.Owasp.ArgLength,
			ArgNameLength:                 config.Owasp.ArgNameLength,
			CombinedFileSizes:             config.Owasp.CombinedFileSizes,
			CriticalAnomalyScore:          config.Owasp.CriticalAnomalyScore,
			CRSValidateUTF8Encoding:       config.Owasp.CRSValidateUTF8Encoding,
			ErrorAnomalyScore:             config.Owasp.ErrorAnomalyScore,
			HTTPViolationScoreThreshold:   config.Owasp.HTTPViolationScoreThreshold,
			InboundAnomalyScoreThreshold:  config.Owasp.InboundAnomalyScoreThreshold,
			LFIScoreThreshold:             config.Owasp.LFIScoreThreshold,
			MaxFileSize:                   config.Owasp.MaxFileSize,
			MaxNumArgs:                    config.Owasp.MaxNumArgs,
			NoticeAnomalyScore:            config.Owasp.NoticeAnomalyScore,
			ParanoiaLevel:                 config.Owasp.ParanoiaLevel,
			PHPInjectionScoreThreshold:    config.Owasp.PHPInjectionScoreThreshold,
			RCEScoreThreshold:             config.Owasp.RCEScoreThreshold,
			RestrictedExtensions:          config.Owasp.RestrictedExtensions,
			RestrictedHeaders:             config.Owasp.RestrictedHeaders,
			RFIScoreThreshold:             config.Owasp.RFIScoreThreshold,
			SessionFixationScoreThreshold: config.Owasp.SessionFixationScoreThreshold,
			SQLInjectionScoreThreshold:    config.Owasp.SQLInjectionScoreThreshold,
			XSSScoreThreshold:             config.Owasp.XSSScoreThreshold,
			TotalArgLength:                config.Owasp.TotalArgLength,
			WarningAnomalyScore:           config.Owasp.WarningAnomalyScore,
		})
		if err != nil {
			Error.Fatal(err)
			return false
		}
		Info.Printf("OWASP settings created with the following parameters:\n%v", owasp)
		Info.Println(" - AllowedHTTPVersions:", owasp.AllowedHTTPVersions)
		Info.Println(" - AllowedMethods:", owasp.AllowedMethods)
		Info.Println(" - AllowedRequestContentType:", owasp.AllowedRequestContentType)
		Info.Println(" - ArgLength:", owasp.ArgLength)
		Info.Println(" - ArgNameLength:", owasp.ArgNameLength)
		Info.Println(" - CombinedFileSizes:", owasp.CombinedFileSizes)
		Info.Println(" - CriticalAnomalyScore:", owasp.CriticalAnomalyScore)
		Info.Println(" - CRSValidateUTF8Encoding:", owasp.CRSValidateUTF8Encoding)
		Info.Println(" - ErrorAnomalyScore:", owasp.ErrorAnomalyScore)
		Info.Println(" - HTTPViolationScoreThreshold:", owasp.HTTPViolationScoreThreshold)
		Info.Println(" - InboundAnomalyScoreThreshold:", owasp.InboundAnomalyScoreThreshold)
		Info.Println(" - LFIScoreThreshold:", owasp.LFIScoreThreshold)
		Info.Println(" - MaxFileSize:", owasp.MaxFileSize)
		Info.Println(" - MaxNumArgs:", owasp.MaxNumArgs)
		Info.Println(" - NoticeAnomalyScore:", owasp.NoticeAnomalyScore)
		Info.Println(" - ParanoiaLevel:", owasp.ParanoiaLevel)
		Info.Println(" - PHPInjectionScoreThreshold:", owasp.PHPInjectionScoreThreshold)
		Info.Println(" - RCEScoreThreshold:", owasp.RCEScoreThreshold)
		Info.Println(" - RestrictedHeaders:", owasp.RestrictedHeaders)
		Info.Println(" - RFIScoreThreshold:", owasp.RFIScoreThreshold)
		Info.Println(" - SessionFixationScoreThreshold:", owasp.SessionFixationScoreThreshold)
		Info.Println(" - SQLInjectionScoreThreshold:", owasp.SQLInjectionScoreThreshold)
		Info.Println(" - XssScoreThreshold:", owasp.XSSScoreThreshold)
		Info.Println(" - TotalArgLength:", owasp.TotalArgLength)
		Info.Println(" - WarningAnomalyScore:", owasp.WarningAnomalyScore)

	} else {

		owasp, err := client.UpdateOWASP(&fastly.UpdateOWASPInput{
			Service:                       serviceID,
			ID:                            wafID,
			OWASPID:                       owasp.ID,
			AllowedHTTPVersions:           config.Owasp.AllowedHTTPVersions,
			AllowedMethods:                config.Owasp.AllowedMethods,
			AllowedRequestContentType:     config.Owasp.AllowedRequestContentType,
			ArgLength:                     config.Owasp.ArgLength,
			ArgNameLength:                 config.Owasp.ArgNameLength,
			CombinedFileSizes:             config.Owasp.CombinedFileSizes,
			CriticalAnomalyScore:          config.Owasp.CriticalAnomalyScore,
			CRSValidateUTF8Encoding:       config.Owasp.CRSValidateUTF8Encoding,
			ErrorAnomalyScore:             config.Owasp.ErrorAnomalyScore,
			HTTPViolationScoreThreshold:   config.Owasp.HTTPViolationScoreThreshold,
			InboundAnomalyScoreThreshold:  config.Owasp.InboundAnomalyScoreThreshold,
			LFIScoreThreshold:             config.Owasp.LFIScoreThreshold,
			MaxFileSize:                   config.Owasp.MaxFileSize,
			MaxNumArgs:                    config.Owasp.MaxNumArgs,
			NoticeAnomalyScore:            config.Owasp.NoticeAnomalyScore,
			ParanoiaLevel:                 config.Owasp.ParanoiaLevel,
			PHPInjectionScoreThreshold:    config.Owasp.PHPInjectionScoreThreshold,
			RCEScoreThreshold:             config.Owasp.RCEScoreThreshold,
			RestrictedExtensions:          config.Owasp.RestrictedExtensions,
			RestrictedHeaders:             config.Owasp.RestrictedHeaders,
			RFIScoreThreshold:             config.Owasp.RFIScoreThreshold,
			SessionFixationScoreThreshold: config.Owasp.SessionFixationScoreThreshold,
			SQLInjectionScoreThreshold:    config.Owasp.SQLInjectionScoreThreshold,
			XSSScoreThreshold:             config.Owasp.XSSScoreThreshold,
			TotalArgLength:                config.Owasp.TotalArgLength,
			WarningAnomalyScore:           config.Owasp.WarningAnomalyScore,
		})
		if err != nil {
			Error.Fatal(err)
			return false
		}
		Info.Println("OWASP settings updated with the following settings:")
		Info.Println(" - AllowedHTTPVersions:", owasp.AllowedHTTPVersions)
		Info.Println(" - AllowedMethods:", owasp.AllowedMethods)
		Info.Println(" - AllowedRequestContentType:", owasp.AllowedRequestContentType)
		Info.Println(" - ArgLength:", owasp.ArgLength)
		Info.Println(" - ArgNameLength:", owasp.ArgNameLength)
		Info.Println(" - CombinedFileSizes:", owasp.CombinedFileSizes)
		Info.Println(" - CriticalAnomalyScore:", owasp.CriticalAnomalyScore)
		Info.Println(" - CRSValidateUTF8Encoding:", owasp.CRSValidateUTF8Encoding)
		Info.Println(" - ErrorAnomalyScore:", owasp.ErrorAnomalyScore)
		Info.Println(" - HTTPViolationScoreThreshold:", owasp.HTTPViolationScoreThreshold)
		Info.Println(" - InboundAnomalyScoreThreshold:", owasp.InboundAnomalyScoreThreshold)
		Info.Println(" - LFIScoreThreshold:", owasp.LFIScoreThreshold)
		Info.Println(" - MaxFileSize:", owasp.MaxFileSize)
		Info.Println(" - MaxNumArgs:", owasp.MaxNumArgs)
		Info.Println(" - NoticeAnomalyScore:", owasp.NoticeAnomalyScore)
		Info.Println(" - ParanoiaLevel:", owasp.ParanoiaLevel)
		Info.Println(" - PHPInjectionScoreThreshold:", owasp.PHPInjectionScoreThreshold)
		Info.Println(" - RCEScoreThreshold:", owasp.RCEScoreThreshold)
		Info.Println(" - RestrictedHeaders:", owasp.RestrictedHeaders)
		Info.Println(" - RFIScoreThreshold:", owasp.RFIScoreThreshold)
		Info.Println(" - SessionFixationScoreThreshold:", owasp.SessionFixationScoreThreshold)
		Info.Println(" - SQLInjectionScoreThreshold:", owasp.SQLInjectionScoreThreshold)
		Info.Println(" - XssScoreThreshold:", owasp.XSSScoreThreshold)
		Info.Println(" - TotalArgLength:", owasp.TotalArgLength)
		Info.Println(" - WarningAnomalyScore:", owasp.WarningAnomalyScore)
		return true
	}
	return true
}

// DeleteLogsCall removes logging endpoints
func DeleteLogsCall(client fastly.Client, serviceID, apiKey string, config TOMLConfig, version int) bool {

	err := client.DeleteSyslog(&fastly.DeleteSyslogInput{
		Service: serviceID,
		Version: version,
		Name:    config.Weblog.Name,
	})
	if err != nil {
		fmt.Print(err)
		return false
	}
	Info.Println("Deleted Web logging endpoint: " + config.Weblog.Name)

	err = client.DeleteSyslog(&fastly.DeleteSyslogInput{
		Service: serviceID,
		Version: version,
		Name:    config.Waflog.Name,
	})
	if err != nil {
		fmt.Print(err)
		return false
	}
	Info.Println("Deleted Waf logging endpoint: " + config.Weblog.Name)

	//first find if we have any PX conditions
	conditions, err := client.ListConditions(&fastly.ListConditionsInput{
		Service: serviceID,
		Version: version,
	})

	if err != nil {
		Error.Fatal(err)
		return false
	}
	for _, condition := range conditions {
		//do we have a condition name waf_prefetch, if not create one
		//iterate through returned conditions check if any say waf_prefetch if not lets configure the service
		if strings.EqualFold(condition.Name, "waf-soc-with-px") {

			err = client.DeleteCondition(&fastly.DeleteConditionInput{
				Service: serviceID,
				Version: version,
				Name:    "waf-soc-with-px",
			})
			if err != nil {
				Error.Fatal(err)
				return false
			}
			Info.Println("WAF PerimeterX logging condition: 'waf-soc-with-px' deleted")

		}
	}

	return true

}

// DeprovisionWAF removes a WAF from a service
func DeprovisionWAF(client fastly.Client, serviceID, apiKey string, config TOMLConfig, version int) bool {
	/*
		To Remove
		1. Delete response
		2. Delete prefetch
		3. Delete WAF
	*/

	//get current waf objects
	wafs, err := client.ListWAFs(&fastly.ListWAFsInput{
		Service: serviceID,
		Version: version,
	})

	if err != nil {
		Error.Fatal(err)
		return false
	}

	if len(wafs) == 0 {
		Error.Printf("No WAF object exists in current service %s version #%v .. exiting", serviceID, version)
		return false
	}

	for index, waf := range wafs {

		//remove WAF Logging
		result := DeleteLogsCall(client, serviceID, apiKey, config, version)
		Info.Printf("Deleting WAF #%v Logging", index+1)
		if !result {
			Error.Printf("Deleting WAF #%v Logging: %s", index+1, err)
		}

		Info.Printf("Deleting WAF #%v Container", index+1)
		//remove WAF container
		err = client.DeleteWAF(&fastly.DeleteWAFInput{
			Service: serviceID,
			Version: version,
			ID:      waf.ID,
		})
		if err != nil {
			Error.Print(err)
			return false
		}

		//remove WAF Response Object
		Info.Printf("Deleting WAF #%v Response Condition", index+1)
		client.DeleteResponseObject(&fastly.DeleteResponseObjectInput{
			Service: serviceID,
			Version: version,
			Name:    "WAF_Response",
		})
		if err != nil {
			Error.Print(err)
			return false
		}

		//remove WAF Prefetch condition
		Info.Printf("Deleting WAF #%v Prefetch Condition", index+1)
		err = client.DeleteCondition(&fastly.DeleteConditionInput{
			Service: serviceID,
			Version: version,
			Name:    "WAF_Prefetch",
		})
		if err != nil {
			Error.Print(err)
			return false
		}

		//remove VCL Snippet
		Info.Printf("Deleting WAF #%v VCL Snippet", index+1)
		apiCall := config.APIEndpoint + "/service/" + serviceID + "/version/" + strconv.Itoa(version) + "/snippet/" + config.Vclsnippet.Name
		//get list of current snippets
		_, err := resty.R().
			SetHeader("Accept", "application/json").
			SetHeader("Fastly-Key", apiKey).
			Delete(apiCall)

		//check if we had an issue with our call
		if err != nil {
			Error.Printf("Deleting WAF #%v VCL Snippet", index+1)
		}

	}

	return true
}

func provisionWAF(client fastly.Client, serviceID, apiKey string, config TOMLConfig, version int) string {

	//create new conditions
	if prefetchCondition(client, serviceID, version, config) {
		Info.Println("successfully created prefetch condition: WAF_Prefetch")
	} else {
		Error.Printf("Issue creating prefetch condition..")
	}

	//create response object
	if responseObject(client, serviceID, version, config) {
		Info.Println("successfully created response object: WAF_Response")
	} else {
		Error.Printf("Issue creating response object..")
	}

	//create VCL Snippet
	if vclSnippet(serviceID, apiKey, version, config) {
		Info.Println("successfully created vcl snippet: Fastly_WAF_Snippet")
	} else {
		Error.Printf("Issue creating vcl snippet..")
	}

	//create WAF container
	wafContainerStatus, wafID := wafContainer(client, serviceID, version, config)
	if wafContainerStatus {
		Info.Println("successfully created WAF container")
	} else {
		Error.Printf("Issue creating WAF container..")
		os.Exit(1)
	}

	//set OWASP parameters
	if createOWASP(client, serviceID, wafID, version, config) {
		Info.Println("successfully created OWASP settings")
	} else {
		Error.Printf("Fatal issue creating OWASP settings..")
		os.Exit(1)
	}

	//set logging parameters
	if FastlyLogging(client, serviceID, version, config) {
		Info.Println("successfully created logging settings")
	} else {
		Error.Printf("Fatal issue creating logging settings..")
		os.Exit(1)
	}

	return wafID
}

// FindServiceID retrives a SID using the Fastly API
func FindServiceID(domain, apiKey, apiEndpoint string) string {
	//Finds the service ID of the provided domain to power other calls

	//API Endpoint to call for domain searches
	apiCall := apiEndpoint + "/admin/domain_search"

	//make the call
	resp, err := resty.R().
		SetQueryString("domain_name="+domain).
		SetHeader("Accept", "application/json").
		SetHeader("Fastly-Key", apiKey).
		Get(apiCall)

	//check if we had an issue with our call
	if err != nil {
		Error.Println("Error with API call: ", err)
		os.Exit(1)
	}

	//unmarshal the response and extract the service id
	body := Service{}
	json.Unmarshal([]byte(resp.String()), &body)

	if body.ServiceID == "" {
		Error.Println("Could not find the service ID for domain: " + domain + " please make sure it exists")
		os.Exit(1)
	}

	Info.Println("Found service id: " + body.ServiceID + " for domain: " + domain)

	return body.ServiceID
}

func validateVersion(client fastly.Client, serviceID string, version int) bool {
	valid, _, err := client.ValidateVersion(&fastly.ValidateVersionInput{
		Service: serviceID,
		Version: version,
	})
	if err != nil {
		Error.Fatal(err)
		return false
	}
	if !valid {
		Error.Println("Version invalid")
		return false
	}
	Info.Printf("Config Version %v Validated successfully", version)
	return true

}

/*
func emergencyConfig() {

}

func sslConfig() {

}
*/

func tagsConfig(apiEndpoint, apiKey, serviceID, wafID string, client fastly.Client, config TOMLConfig) {
	//Work on Tags first
	//API Endpoint to call for domain searches
	apiCall := apiEndpoint + "/wafs/tags"

	//cleanup action
	action := strings.TrimSpace(config.Action)
	action = strings.ToLower(action)

	//make the call

	for _, tag := range config.Tags {

		resp, err := resty.R().
			SetQueryString("filter[name]="+tag+"&include=rules").
			SetHeader("Accept", "application/vnd.api+json").
			SetHeader("Fastly-Key", apiKey).
			Get(apiCall)

		//check if we had an issue with our call
		if err != nil {
			Error.Println("Error with API call: " + apiCall)
			os.Exit(1)
		}

		//unmarshal the response and extract the service id
		body := RuleList{}
		json.Unmarshal([]byte(resp.String()), &body)

		if len(body.Data) == 0 {
			Error.Println("Could not find any rules with tag: " + tag + " please make sure it exists..moving to the next tag")
			continue
		}

		//set rule action on our tags
		apiCall := apiEndpoint + "/service/" + serviceID + "/wafs/" + wafID + "/rule_statuses"

		resp, err = resty.R().
			SetHeader("Accept", "application/vnd.api+json").
			SetHeader("Fastly-Key", apiKey).
			SetHeader("Content-Type", "application/vnd.api+json").
			SetBody(`{"data": {"attributes": {"status": "` + action + `","name": "` + tag + `","force": true},"id": "` + wafID + `","type": "rule_status"}}`).
			Post(apiCall)

		//check if we had an issue with our call
		if err != nil {
			Error.Println("Error with API call: " + apiCall)
			Error.Println(resp.String())
			os.Exit(1)
		}

		//check if our response was ok
		if resp.Status() == "200 OK" {
			Info.Printf(action+" %d rule on the WAF for tag: "+tag, len(body.Data))
		} else {
			Error.Println("Could not set status: "+action+" on rule tag: "+tag+" the response was: ", resp.String())
		}
	}
}

func changeStatus(apiEndpoint, apiKey, wafID, status string) {
	apiCall := apiEndpoint + "/wafs/" + wafID + "/" + status

	resp, err := resty.R().
		SetHeader("Accept", "application/vnd.api+json").
		SetHeader("Fastly-Key", apiKey).
		SetHeader("Content-Type", "application/vnd.api+json").
		SetBody(`{"data": {"id": "` + wafID + `","type": "waf"}}`).
		Patch(apiCall)

	//check if we had an issue with our call
	if err != nil {
		Error.Println("Error with API call: " + apiCall)
		Error.Println(resp.String())
		os.Exit(1)
	}

	//check if our response was ok
	if resp.Status() == "202 Accepted" {
		Info.Printf("WAF %s status was changed to %s", wafID, status)
	} else {
		Error.Println("Could not change the status of WAF " + wafID + " to " + status)
		Error.Println("We received the following status code: " + resp.Status() + " with response from the API: " + resp.String())
	}

}

func rulesConfig(apiEndpoint, apiKey, serviceID, wafID string, client fastly.Client, config TOMLConfig) {
	//cleanup action
	action := strings.TrimSpace(config.Action)
	action = strings.ToLower(action)

	//implement individual rule management here
	for _, rule := range config.Rules {

		ruleID := strconv.FormatInt(rule, 10)

		//set rule action on our tags
		apiCall := apiEndpoint + "/service/" + serviceID + "/wafs/" + wafID + "/rules/" + ruleID + "/rule_status"

		resp, err := resty.R().
			SetHeader("Accept", "application/vnd.api+json").
			SetHeader("Fastly-Key", apiKey).
			SetHeader("Content-Type", "application/vnd.api+json").
			SetBody(`{"data": {"attributes": {"status": "` + action + `"},"id": "` + wafID + `-` + ruleID + `","type": "rule_status"}}`).
			Patch(apiCall)

		//check if we had an issue with our call
		if err != nil {
			Error.Println("Error with API call: " + apiCall)
			Error.Println(resp.String())
			os.Exit(1)
		}

		//check if our response was ok
		if resp.Status() == "200 OK" {
			Info.Printf("Rule %s was configured in the WAF with action %s", ruleID, config.Action)
		} else {
			Error.Println("Could not set status: "+config.Action+" on rule tag: "+ruleID+" the response was: ", resp.String())
		}
	}
}

// DefaultRuleDisabled disables rule IDs defined in the configuration file
func DefaultRuleDisabled(apiEndpoint, apiKey, serviceID, wafID string, client fastly.Client, config TOMLConfig) {

	//implement individual rule management here
	for _, rule := range config.DisabledRules {

		ruleID := strconv.FormatInt(rule, 10)

		//set rule action on our tags
		apiCall := apiEndpoint + "/service/" + serviceID + "/wafs/" + wafID + "/rules/" + ruleID + "/rule_status"

		resp, err := resty.R().
			SetHeader("Accept", "application/vnd.api+json").
			SetHeader("Fastly-Key", apiKey).
			SetHeader("Content-Type", "application/vnd.api+json").
			SetBody(`{"data": {"attributes": {"status": "disabled"},"id": "` + wafID + `-` + ruleID + `","type": "rule_status"}}`).
			Patch(apiCall)

		//check if we had an issue with our call
		if err != nil {
			Error.Println("Error with API call: " + apiCall)
			Error.Println(resp.String())
			os.Exit(1)
		}

		//check if our response was ok
		if resp.Status() == "200 OK" {
			Info.Printf("Rule %s was configured in the WAF with action disabled via disabledrules parameter", ruleID)
		} else {
			Error.Println("Could not set status: "+config.Action+" on rule tag: "+ruleID+" the response was: ", resp.String())
		}
	}
}

// WithPXCondition adds a condition if PX is present to avoid null host and request ID logging
func WithPXCondition(client fastly.Client, serviceID string, version int, config TOMLConfig) bool {

	conditions, err := client.ListConditions(&fastly.ListConditionsInput{
		Service: serviceID,
		Version: version,
	})

	if err != nil {
		Error.Fatal(err)
		return false
	}
	for _, condition := range conditions {
		//do we have a condition name waf_prefetch, if not create one
		//iterate through returned conditions check if any say waf_prefetch if not lets configure the service
		if strings.EqualFold(condition.Name, "waf-soc-with-px") {
			Error.Println("WAF PerimeterX logging condition already exists with name: " + condition.Name + "..skipping creating conditions")
			return false
		}
	}

	Info.Printf("WAF enabled with PerimeterX, creating logging condition: waf-soc-with-px")
	_, err = client.CreateCondition(&fastly.CreateConditionInput{
		Service:   serviceID,
		Version:   version,
		Name:      "waf-soc-with-px",
		Statement: "req.http.x-request-id",
		Type:      "RESPONSE",
		Priority:  10,
	})

	if err != nil {
		Error.Fatal(err)
		return false
	}

	//update syslog endpoints
	Info.Printf("WAF enabled with PerimeterX, applying condition 'waf-soc-with-px' to web logs %s", config.Weblog.Name)
	_, err = client.UpdateSyslog(&fastly.UpdateSyslogInput{
		Service:           serviceID,
		Version:           version,
		Name:              config.Weblog.Name,
		ResponseCondition: "waf-soc-with-px",
	})

	if err != nil {
		Error.Fatal(err)
		return false
	}

	Info.Printf("WAF enabled with PerimeterX, applying condition 'waf-soc-with-px' to waf logs %s", config.Waflog.Name)
	_, err = client.UpdateSyslog(&fastly.UpdateSyslogInput{
		Service:           serviceID,
		Version:           version,
		Name:              config.Waflog.Name,
		ResponseCondition: "waf-soc-with-px",
	})

	if err != nil {
		Error.Fatal(err)
		return false
	}

	return true

}

// PatchRules function patches a rule set after a status of a rule has been changed
func PatchRules(serviceID, wafID string, client fastly.Client) bool {

	_, err := client.UpdateWAFRuleSets(&fastly.UpdateWAFRuleRuleSetsInput{
		Service: serviceID,
		ID:      wafID,
	})

	if err != nil {
		Error.Print(err)
		return false

	}
	return true
}

// changeConfigurationSet function allows you to change a config set for a WAF object
func setConfigurationSet(wafID, configurationSet string, client fastly.Client) bool {

	wafs := []fastly.ConfigSetWAFs{{ID:wafID}}

	_, err := client.UpdateWAFConfigSet(&fastly.UpdateWAFConfigSetInput{
		WAFList:wafs,
		ConfigSetID: configurationSet,
	})


	//check if we had an issue with our call
	if err != nil {
		Error.Println("Error setting configuration set ID: " + configurationSet)
		return false
	}

	return true

}

// getConfigurationSets function provides a listing of all config sets
func getConfigurationSets(apiEndpoint, apiKey string) bool {
	//set our API call
	apiCall := apiEndpoint + "/wafs/configuration_sets"

	resp, err := resty.R().
		SetHeader("Accept", "application/vnd.api+json").
		SetHeader("Fastly-Key", apiKey).
		SetHeader("Content-Type", "application/vnd.api+json").
		Get(apiCall)

	//check if we had an issue with our call
	if err != nil {
		Error.Println("Error with API call: " + apiCall)
		Error.Println(resp.String())
		return false
	}

	//unmarshal the response and extract the service id
	body := ConfigSetList{}
	json.Unmarshal([]byte(resp.String()), &body)

	if len(body.Data) == 0 {
		Error.Println("No Configuration Sets found")
		return false
	}


	json.Unmarshal([]byte(resp.String()), &body)

	if len(body.Data) == 0 {
		Error.Println("No Fastly Rules found")
		return false
	}

	result := PagesOfConfigurationSets{[]ConfigSetList{}}
	result.page = append(result.page, body)

	currentpage := body.Meta.CurrentPage
	totalpages := body.Meta.TotalPages

	Info.Printf("Read Total Pages: %d with %d rules", body.Meta.TotalPages, body.Meta.RecordCount)

	// iterate through pages collecting all rules
	for currentpage := currentpage + 1; currentpage <= totalpages; currentpage++ {

		Info.Printf("Reading page: %d out of %d", currentpage, totalpages)
		//set our API call
		apiCall := apiEndpoint + "/wafs/configuration_sets?page[number]=" + strconv.Itoa(currentpage)

		resp, err := resty.R().
			SetHeader("Accept", "application/vnd.api+json").
			SetHeader("Fastly-Key", apiKey).
			SetHeader("Content-Type", "application/vnd.api+json").
			Get(apiCall)

		//check if we had an issue with our call
		if err != nil {
			Error.Println("Error with API call: " + apiCall)
			Error.Println(resp.String())
			return false
		}

		//unmarshal the response and extract the service id
		body := ConfigSetList{}
		json.Unmarshal([]byte(resp.String()), &body)
		result.page = append(result.page, body)
	}

	for _, p := range result.page {
		for _, c := range p.Data {
			Info.Printf("- Configuration Set %s -  %s - Active: %t \n", c.ID, c.Attributes.Name, c.Attributes.Active)
		}
	}

	return true

}

// getRuleInfo function
func getRuleInfo(apiEndpoint, apiKey, ruleID string) Rule {
		rule := Rule{}
		//set our API call
		apiCall := apiEndpoint + "/wafs/rules?page[size]=10&page[number]=1&filter[rule_id]=" + ruleID

		resp, err := resty.R().
			SetHeader("Accept", "application/vnd.api+json").
			SetHeader("Fastly-Key", apiKey).
			SetHeader("Content-Type", "application/vnd.api+json").
			Get(apiCall)

		//check if we had an issue with our call
		if err != nil {
			Error.Println("Error with API call: " + apiCall)
			Error.Println(resp.String())
		}

		//unmarshal the response and extract the service id
		body := RuleList{}
		json.Unmarshal([]byte(resp.String()), &body)

		if len(body.Data) == 0 {
			Error.Println("No Fastly Rules found")
		}

		for _, r := range body.Data{
			rule = r
		}

		return rule
}

// getRules functions lists all rules for a WAFID and their status
func getRules(apiEndpoint, apiKey, serviceID, wafID string) bool {
	//set our API call
	apiCall := apiEndpoint + "/service/" + serviceID + "/wafs/" + wafID + "/rule_statuses"

	resp, err := resty.R().
		SetHeader("Accept", "application/vnd.api+json").
		SetHeader("Fastly-Key", apiKey).
		SetHeader("Content-Type", "application/vnd.api+json").
		Get(apiCall)

	//check if we had an issue with our call
	if err != nil {
		Error.Println("Error with API call: " + apiCall)
		Error.Println(resp.String())
		return false
	}

	//unmarshal the response and extract the service id
	body := RuleList{}
	json.Unmarshal([]byte(resp.String()), &body)

	if len(body.Data) == 0 {
		Error.Println("No Fastly Rules found")
		return false
	}

	result := PagesOfRules{[]RuleList{}}
	result.page = append(result.page, body)

	currentpage := body.Meta.CurrentPage
	totalpages := body.Meta.TotalPages

	Info.Printf("Read Total Pages: %d with %d rules", body.Meta.TotalPages, body.Meta.RecordCount)

	// iterate through pages collecting all rules
	for currentpage := currentpage + 1; currentpage <= totalpages; currentpage++ {

		Info.Printf("Reading page: %d out of %d", currentpage, totalpages)
		//set our API call
		apiCall := apiEndpoint + "/service/" + serviceID + "/wafs/" + wafID + "/rule_statuses?page[size]=200&page[number]=" + strconv.Itoa(currentpage)

		resp, err := resty.R().
			SetHeader("Accept", "application/vnd.api+json").
			SetHeader("Fastly-Key", apiKey).
			SetHeader("Content-Type", "application/vnd.api+json").
			Get(apiCall)

		//check if we had an issue with our call
		if err != nil {
			Error.Println("Error with API call: " + apiCall)
			Error.Println(resp.String())
			return false
		}

		//unmarshal the response and extract the service id
		body := RuleList{}
		json.Unmarshal([]byte(resp.String()), &body)
		result.page = append(result.page, body)
	}

	var log []Rule
	var disabled []Rule
	var block []Rule

	for _, p := range result.page {
			for _, r := range p.Data {
			if r.Attributes.Status == "log" {
				log = append(log, r)
			} else if r.Attributes.Status == "block" {
				block = append(block, r)
			} else if r.Attributes.Status == "disabled" {
				disabled = append(disabled, r)
			}
		}
	}

	Info.Println("- Blocking Rules")
	for _, r := range block {
		info := getRuleInfo(apiEndpoint, apiKey, r.Attributes.ModsecRuleID)
		Info.Printf("- Rule ID: %s\tStatus: %s\tParanoia: %d\tOrigin: %s\tMessage: %s\n",
			r.Attributes.ModsecRuleID, r.Attributes.Status, info.Attributes.ParanoiaLevel,
				info.Attributes.Origin, info.Attributes.Message)
	}

	Info.Println("- Logging Rules")
	for _, r := range log {
		info := getRuleInfo(apiEndpoint, apiKey, r.Attributes.ModsecRuleID)
		Info.Printf("- Rule ID: %s\tStatus: %s\tParanoia: %d\tOrigin: %s\tMessage: %s\n",
			r.Attributes.ModsecRuleID, r.Attributes.Status, info.Attributes.ParanoiaLevel,
			info.Attributes.Origin, info.Attributes.Message)
	}

	Info.Println("- Disabled Rules")
	for _, r := range disabled {
		info := getRuleInfo(apiEndpoint, apiKey, r.Attributes.ModsecRuleID)
		Info.Printf("- Rule ID: %s\tStatus: %s\tParanoia: %d\tOrigin: %s\tMessage: %s\n",
			r.Attributes.ModsecRuleID, r.Attributes.Status, info.Attributes.ParanoiaLevel,
			info.Attributes.Origin, info.Attributes.Message)
	}
	return true
}

// getAllRules function lists all the rules with in the Fastly API
func getAllRules(apiEndpoint, apiKey, ConfigID string) bool {

	if ConfigID == "" {
		//set our API call
		apiCall := apiEndpoint + "/wafs/rules?page[size]=200&page[number]=1"

		resp, err := resty.R().
			SetHeader("Accept", "application/vnd.api+json").
			SetHeader("Fastly-Key", apiKey).
			SetHeader("Content-Type", "application/vnd.api+json").
			Get(apiCall)

		//check if we had an issue with our call
		if err != nil {
			Error.Println("Error with API call: " + apiCall)
			Error.Println(resp.String())
			return false
		}

		//unmarshal the response and extract the service id
		body := RuleList{}
		json.Unmarshal([]byte(resp.String()), &body)

		if len(body.Data) == 0 {
			Error.Println("No Fastly Rules found")
			return false
		}

		result := PagesOfRules{[]RuleList{}}
		result.page = append(result.page, body)

		currentpage := body.Meta.CurrentPage
		totalpages := body.Meta.TotalPages

		Info.Printf("Read Total Pages: %d with %d rules", body.Meta.TotalPages, body.Meta.RecordCount)

		// iterate through pages collecting all rules
		for currentpage := currentpage + 1; currentpage <= totalpages; currentpage++ {

			Info.Printf("Reading page: %d out of %d", currentpage, totalpages)
			//set our API call
			apiCall := apiEndpoint + "/wafs/rules?page[size]=200&page[number]=" + strconv.Itoa(currentpage)

			resp, err := resty.R().
				SetHeader("Accept", "application/vnd.api+json").
				SetHeader("Fastly-Key", apiKey).
				SetHeader("Content-Type", "application/vnd.api+json").
				Get(apiCall)

			//check if we had an issue with our call
			if err != nil {
				Error.Println("Error with API call: " + apiCall)
				Error.Println(resp.String())
				return false
			}

			//unmarshal the response and extract the service id
			body := RuleList{}
			json.Unmarshal([]byte(resp.String()), &body)
			result.page = append(result.page, body)
		}

		var owasp []Rule
		var fastly []Rule
		var trustwave []Rule

		for _, p := range result.page {
			for _, r := range p.Data {
				if r.Attributes.Origin == "owasp" {
					owasp = append(owasp, r)
				} else if r.Attributes.Origin == "trustwave" {
					trustwave = append(trustwave, r)
				} else if r.Attributes.Origin == "fastly" {
					fastly = append(fastly, r)
				}
			}
		}

		Info.Println("- OWASP Rules")
		for _, r := range owasp {
			Info.Printf("- Rule ID: %s\tParanoia: %d\tVersion: %s\tMessage: %s\n", r.ID, r.Attributes.ParanoiaLevel, r.Attributes.Version, r.Attributes.Message)
		}

		Info.Println("- Fastly Rules")
		for _, r := range fastly {
			Info.Printf("- Rule ID: %s\tParanoia: %d\tVersion: %s\tMessage: %s\n", r.ID, r.Attributes.ParanoiaLevel, r.Attributes.Version, r.Attributes.Message)
		}

		Info.Println("- Trustwave Rules")
		for _, r := range trustwave {
			Info.Printf("- Rule ID: %s\tParanoia: %d\tVersion: %s\tMessage: %s\n", r.ID, r.Attributes.ParanoiaLevel, r.Attributes.Version, r.Attributes.Message)
		}
	} else {

		//set our API call
		apiCall := apiEndpoint + "/wafs/rules?filter[configuration_set_id]=" + ConfigID + "&page[size]=200&page[number]=1"

		resp, err := resty.R().
			SetHeader("Accept", "application/vnd.api+json").
			SetHeader("Fastly-Key", apiKey).
			SetHeader("Content-Type", "application/vnd.api+json").
			Get(apiCall)

		//check if we had an issue with our call
		if err != nil {
			Error.Println("Error with API call: " + apiCall)
			Error.Println(resp.String())
			return false
		}

		//unmarshal the response and extract the service id
		body := RuleList{}
		json.Unmarshal([]byte(resp.String()), &body)

		if len(body.Data) == 0 {
			Error.Println("No Fastly Rules found")
			return false
		}

		result := PagesOfRules{[]RuleList{}}
		result.page = append(result.page, body)

		currentpage := body.Meta.CurrentPage
		totalpages := body.Meta.TotalPages

		Info.Printf("Read Total Pages: %d with %d rules", body.Meta.TotalPages, body.Meta.RecordCount)

		// iterate through pages collecting all rules
		for currentpage := currentpage + 1; currentpage <= totalpages; currentpage++ {

			Info.Printf("Reading page: %d out of %d", currentpage, totalpages)
			//set our API call
			apiCall := apiEndpoint + "/wafs/rules?filter[configuration_set_id]=" + ConfigID + "&page[size]=200&page[number]=" + strconv.Itoa(currentpage)

			resp, err := resty.R().
				SetHeader("Accept", "application/vnd.api+json").
				SetHeader("Fastly-Key", apiKey).
				SetHeader("Content-Type", "application/vnd.api+json").
				Get(apiCall)

			//check if we had an issue with our call
			if err != nil {
				Error.Println("Error with API call: " + apiCall)
				Error.Println(resp.String())
				return false
			}

			//unmarshal the response and extract the service id
			body := RuleList{}
			json.Unmarshal([]byte(resp.String()), &body)
			result.page = append(result.page, body)
		}

		var owasp []Rule
		var fastly []Rule
		var trustwave []Rule

		for _, p := range result.page {
			for _, r := range p.Data {
				if r.Attributes.Origin == "owasp" {
					owasp = append(owasp, r)
				} else if r.Attributes.Origin == "trustwave" {
					trustwave = append(trustwave, r)
				} else if r.Attributes.Origin == "fastly" {
					fastly = append(fastly, r)
				}
			}
		}

		Info.Println("- OWASP Rules")
		for _, r := range owasp {
			Info.Printf("- Rule ID: %s\tParanoia: %d\tVersion: %s\tMessage: %s\n", r.ID, r.Attributes.ParanoiaLevel, r.Attributes.Version, r.Attributes.Message)
		}

		Info.Println("- Fastly Rules")
		for _, r := range fastly {
			Info.Printf("- Rule ID: %s\tParanoia: %d\tVersion: %s\tMessage: %s\n", r.ID, r.Attributes.ParanoiaLevel, r.Attributes.Version, r.Attributes.Message)
		}

		Info.Println("- Trustwave Rules")
		for _, r := range trustwave {
			Info.Printf("- Rule ID: %s\tParanoia: %d\tVersion: %s\tMessage: %s\n", r.ID, r.Attributes.ParanoiaLevel, r.Attributes.Version, r.Attributes.Message)
		}

	}

	return true

}

func main() {

	// grab a users home directory
	user, err := user.Current()
	if err != nil {
		fmt.Println("error reading current user name : ", err)
		os.Exit(1)
	}

	HOMEDIRECTORY := user.HomeDir

	domain := flag.String("domain", "", "[Required] Domain to Provision, you can use Service ID alternatively")
	serviceID := flag.String("serviceid", "", "[Required] Service ID to Provision")
	apiKey := flag.String("apikey", "", "[Required] API Key to use")
	apiEndpoint := flag.String("apiendpoint", "https://api.fastly.com", "Fastly API endpoint to use.")
	configFile := flag.String("config", HOMEDIRECTORY + "/.waflyctl.toml", "Location of configuration file for waflyctl.")

	ListAllRules := flag.String("list-all-rules", "", "List all rules available on the Fastly platform for a given configuration set. Must pass a configuration set ID")
	ListRules := flag.Bool("list-rules", false, "List current WAF rules and their status")

	ListConfigSet := flag.Bool("list-configuration-sets", false, "List all configuration sets and their status")
	ConfigurationSet := flag.String("configuration-set", "", "Changes WAF configuration set to the provided one]")

	var Rules string
	flag.StringVar(&Rules, "rules", "", "Which rules to apply action on in a comma delimited fashion, overwrites ruleid defined in config file, example: 94011,93110,1000101..")

	var Tags string
	flag.StringVar(&Tags, "tags", "", "Which rules tags to add to the ruleset in a comma delimited fashion, overwrites tags defined in config file, example: OWASP,wordpress,php")

	Action := flag.String("action", "", "Select what action to take on the rules list and rule tags. Also overwrites action defined in config file, choices are: disabled, block, log.")
	EditOWASP := flag.Bool("owasp", false, "When set edits the OWASP object base on the settings in the configuration file.")
	Deprovision := flag.Bool("delete", false, "When set removes a WAF configuration created with waflyctl.")
	LogOnly := flag.Bool("enable-logs-only", false, "Add logging configuration only to the service, the tool will not make any other changes, can be paired with-perimeterx")
	DeleteLogs := flag.Bool("delete-logs", false, "When set removes WAF logging configuration.")
	WithPX := flag.Bool("with-perimeterx", false, "Enable if the customer has perimeterX enabled on the service as well as WAF. Helps fix null value logging.")
	Status := flag.String("status", "", "Disable or Enable the WAF. A disabled WAF will not block any traffic, also disabling a WAF does not change rule statuses on its configure policy. ")
	flag.Parse()

	//check for empty args
	switch {
	case *domain == "" && *serviceID == "":
		fmt.Println("A domain or service ID is required!")
		flag.PrintDefaults()
		os.Exit(1)
	case *apiKey == "":
		fmt.Println("API Key is required!")
		flag.PrintDefaults()
		os.Exit(1)
	case *configFile == "":
		fmt.Println("Config File is required!")
		flag.PrintDefaults()
		os.Exit(1)
	}

	const logo = `
       _.--------._
      .' _|_|_|_|_ '.
     / _|_|_|_|_|_|_ \
    | |_|_|_|_|_|_|_| |
    |_|_|_|_|_|_|_|_|_|
    | |_|_|_|_|_|_|_| |
    | |_|_|_|_|_|_|_| |
     \ -|_|_|_|_|_|- /
      '. -|_|_|_|- .'
        ` + `----------`

	fmt.Println(logo)

	// grab version and build

	fmt.Println("Fastly WAF Control Tool version: " + version + " built on " + date + " by #team-soc")

	//run init to get our logging configured
	var config TOMLConfig
	config = Init(*configFile)

	config.APIEndpoint = *apiEndpoint

	//check if rule action was set on CLI, also check if is the correct status
	if *Action != "" {
		config.Action = ""
		config.Action = *Action

		switch {
		case strings.ToLower(*Action) == "block":
			config.Action = ""
			config.Action = *Action
			Info.Println("using rule action set by CLI: ", *Action)
		case strings.ToLower(*Action) == "log":
			config.Action = ""
			config.Action = *Action
			Info.Println("using rule action set by CLI: ", *Action)
		case strings.ToLower(*Action) == "disabled":
			config.Action = ""
			config.Action = *Action
			Info.Println("using rule action set by CLI: ", *Action)
		default:
			Error.Println("incorrect rule action provided: " + config.Action + " expecting \"disabled\", or \"block\", or \"log\"")
			flag.PrintDefaults()
			os.Exit(1)
		}
	}

	//check status rule action was set on CLI, also check if is the correct status
	if *Status != "" {

		switch {
		case strings.ToLower(*Status) == "enable":
			Info.Println("using rule action set by CLI: ", *Action)
		case strings.ToLower(*Status) == "disable":
			Info.Println("using rule action set by CLI: ", *Action)
		default:
			Error.Println("incorrect status provided: " + config.Action + " expecting \"enable\", or \"disable\"")
			flag.PrintDefaults()
			os.Exit(1)
		}
	}

	//if rules are passed via CLI parse them and replace config parameters
	if Rules != "" {
		config.Rules = nil
		Info.Println("using rule IDS set by CLI:")
		ruleIDs := strings.Split(Rules, ",")
		for _, id := range ruleIDs {
			//cast IDs from string to int
			i, _ := strconv.ParseInt(id, 10, 32)
			Info.Println("- ruleID:", id)
			config.Rules = append(config.Rules, i)

		}
	}

	//if rule tags are passed via CLI parse them and replace config parameters
	if Tags != "" {
		config.Tags = nil
		Info.Println("using tags set by CLI:")
		tags := strings.Split(Tags, ",")
		for _, tag := range tags {
			Info.Println(" - tag name: ", tag)
			config.Tags = append(config.Tags, tag)
		}
	}

	//if rule action is passed via CLI parse them and replace config parameters
	if *Action != "" {
		config.Action = *Action
	}

	//get service ID
	if *serviceID == "" {
		*serviceID = FindServiceID(*domain, *apiKey, config.APIEndpoint)
	}
	//create Fastly client
	client, err := fastly.NewClientForEndpoint(*apiKey, config.APIEndpoint)
	if err != nil {
		Error.Fatal(err)
	}

	//====================================
	/*still need to implement the following:
	if *emergency {
		emergencyConfig()
	}

	if *ssl {
		sslConfig()
	}
	*/

	//====================================

	//get currently activeVersion to be used
	activeVersion := getActiveVersion(*client, *serviceID, *apiKey, config)

	// add logs only to a service
	if *LogOnly {

		Info.Println("Adding logging endpoints only")

		_, version := cloneVersion(*client, *serviceID, *apiKey, config, activeVersion)

		//create VCL Snippet
		if vclSnippet(*serviceID, *apiKey, version, config) {
			Info.Println("successfully created vcl snippet: Fastly_WAF_Snippet")
		} else {
			Error.Printf("Issue creating vcl snippet..")
		}

		//set logging parameters
		if FastlyLogging(*client, *serviceID, version, config) {
			Info.Println("successfully created logging settings")
		} else {
			Error.Printf("Fatal issue creating logging settings..")
			os.Exit(1)
		}

		if *WithPX {
			Info.Printf("WAF enabled with PerimterX, adding logging condition")
			WithPXCondition(*client, *serviceID, version, config)
		}

		//validate the config
		validateVersion(*client, *serviceID, version)
		Info.Println("Completed")
		os.Exit(1)

	}
	// check if is a de-provisioning call
	if *Deprovision {
		_, version := cloneVersion(*client, *serviceID, *apiKey, config, activeVersion)

		result := DeprovisionWAF(*client, *serviceID, *apiKey, config, version)
		if result {
			Info.Printf("Successfully deleted WAF on Service ID %s. Do not forget to activate version %v!", *serviceID, version)
			Info.Printf("Completed")
			os.Exit(1)
		} else {
			Error.Printf("Failed to delete WAF on Service ID %s..see above for details", *serviceID)
			Info.Printf("Completed")
			os.Exit(1)
		}
	}

	// check if is a delete logs parameter was called
	if *DeleteLogs {

		//clone current version
		_, version := cloneVersion(*client, *serviceID, *apiKey, config, activeVersion)

		//delete the logs
		result := DeleteLogsCall(*client, *serviceID, *apiKey, config, version)

		if result {
			Info.Printf("Successfully deleted logging endpint %s and %s in Service ID %s. Remember to activate version %v!", config.Weblog.Name, config.Waflog.Name, *serviceID, version)
			Info.Printf("Completed")
			os.Exit(1)
		} else {
			Error.Printf("Failed to delete logging endpoints on Service ID %s..see above for details", *serviceID)
			Info.Printf("Completed")
			os.Exit(1)
		}
	}

	//enable the WAF feature if is not already on
	checkWAF(*apiKey, config.APIEndpoint)

	Info.Printf("currently working with config version: %v.\n*Note rule, OWASP and tags changes are versionless actions and thus do not generate a new config version*", activeVersion)
	wafs, err := client.ListWAFs(&fastly.ListWAFsInput{
		Service: *serviceID,
		Version: activeVersion,
	})

	if err != nil {
		Error.Fatal(err)
	}

	if len(wafs) != 0 {
		//do rule adjustment here
		for index, waf := range wafs {

			//if no individual tags or rules are set via CLI run both actions
			switch {

			//list configuration sets rules
			case *ListConfigSet:
				Info.Printf("Listing all configuration sets")
				getConfigurationSets(config.APIEndpoint, *apiKey)
				Info.Println("Completed")
				os.Exit(1)

			//list waf rules
			case *ListRules:
				Info.Printf("Listing all rules for WAF ID: %s", waf.ID)
				getRules(config.APIEndpoint, *apiKey, *serviceID, waf.ID)
				Info.Println("Completed")
				os.Exit(1)

			//list all rules for a given configset
			case *ListAllRules != "":
				Info.Printf("Listing all rules under configuration set ID: %s", *ListAllRules)
				ConfigID := *ListAllRules
				getAllRules(config.APIEndpoint, *apiKey, ConfigID)
				Info.Println("Completed")
				os.Exit(1)

			//change a configuration set
			case *ConfigurationSet != "":
				Info.Printf("Changing Configuration Set to: %s", *ConfigurationSet)
				ConfigID := *ConfigurationSet
				setConfigurationSet(waf.ID,ConfigID, *client)
				Info.Println("Completed")
				os.Exit(1)

			case *Status != "":
				Info.Println("Changing WAF Status")
				//rule management
				changeStatus(config.APIEndpoint, *apiKey, waf.ID, *Status)
				Info.Println("Completed")
				os.Exit(1)

			case Tags != "":
				Info.Println("Editing Tags")
				//tags management
				tagsConfig(config.APIEndpoint, *apiKey, *serviceID, waf.ID, *client, config)

				//patch ruleset
				if PatchRules(*serviceID, waf.ID, *client) {
					Info.Println("Rule set successfully patched")

				} else {
					Error.Printf("Issue patching ruleset see above error..")
				}

			case Rules != "":
				Info.Println("Editing Rules")
				//rule management
				rulesConfig(config.APIEndpoint, *apiKey, *serviceID, waf.ID, *client, config)

				//patch ruleset
				if PatchRules(*serviceID, waf.ID, *client) {
					Info.Println("Rule set successfully patched")

				} else {
					Error.Printf("Issue patching ruleset see above error..")
				}

			case *EditOWASP:
				Info.Printf("Editing OWASP settings for WAF #%v", index+1)
				createOWASP(*client, *serviceID, waf.ID, activeVersion, config)

				//patch ruleset
				if PatchRules(*serviceID, waf.ID, *client) {
					Info.Println("Rule set successfully patched")

				} else {
					Error.Printf("Issue patching ruleset see above error..")
				}

			case *WithPX:
				Info.Printf("WAF enabled with PerimterX, adding logging condition")

				//clone current version
				_, version := cloneVersion(*client, *serviceID, *apiKey, config, activeVersion)

				WithPXCondition(*client, *serviceID, version, config)

			default:
				//tags management
				tagsConfig(config.APIEndpoint, *apiKey, *serviceID, waf.ID, *client, config)
				//rule management
				rulesConfig(config.APIEndpoint, *apiKey, *serviceID, waf.ID, *client, config)
				//OWASP
				createOWASP(*client, *serviceID, waf.ID, activeVersion, config)

				//patch ruleset
				if PatchRules(*serviceID, waf.ID, *client) {
					Info.Println("Rule set successfully patched")

				} else {
					Error.Printf("Issue patching ruleset see above error..")
				}
			}

			//validate the config
			validateVersion(*client, *serviceID, activeVersion)
			Info.Println("Completed")
			os.Exit(1)
		}

	} else {
		Warning.Println("Provisioning a new WAF on Service ID: " + *serviceID)

		//clone current version
		_, version := cloneVersion(*client, *serviceID, *apiKey, config, activeVersion)

		//provision a new WAF service
		wafID := provisionWAF(*client, *serviceID, *apiKey, config, version)

		//tags management
		tagsConfig(config.APIEndpoint, *apiKey, *serviceID, wafID, *client, config)

		//rule management
		rulesConfig(config.APIEndpoint, *apiKey, *serviceID, wafID, *client, config)

		//Default Disabled
		DefaultRuleDisabled(config.APIEndpoint, *apiKey, *serviceID, wafID, *client, config)

		if *WithPX {
			Info.Printf("WAF enabled with PerimterX, adding logging condition")
			WithPXCondition(*client, *serviceID, version, config)
		}

		latest, err := client.LatestVersion(&fastly.LatestVersionInput{
			Service: *serviceID,
		})
		if err != nil {
			Error.Fatal(err)
		}

		//patch ruleset
		if PatchRules(*serviceID, wafID, *client) {
			Info.Println("Rule set successfully patched")

		} else {
			Error.Printf("Issue patching ruleset see above error..")
		}

		//validate the config
		validateVersion(*client, *serviceID, latest.Number)
		Info.Println("Completed")
		os.Exit(1)
	}

}
