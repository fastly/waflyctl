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
	"gopkg.in/resty.v1"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"github.com/sethvargo/go-fastly/fastly"
)

var (
	//logging variables
	logFile string
	Trace   *log.Logger
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
)

//init function starts our logger
func Init(

	//configure logging
	infoHandle io.Writer,
	warningHandle io.Writer,
	errorHandle io.Writer, configFile string) tomlConfig {

	//load configs
	var config tomlConfig
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
	file, err := os.OpenFile(config.Logpath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
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

type tomlConfig struct {
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
	XssScoreThreshold			  int
	TotalArgLength                int
	WarningAnomalyScore           int
}

type WeblogSettings struct {
	Name        string
	Address     string
	Port        uint
	Tlscacert   string
	Tlshostname string
	Format      string
}

type VCLSnippetSettings struct {
	Name     string
	Content  string
	Type     string
	Priority int
	Dynamic  int
}

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

type WaflogSettings struct {
	Name        string
	Address     string
	Port        uint
	Tlscacert   string
	Tlshostname string
	Format      string
}

type ResponseSettings struct {
	Name           string
	HttpStatusCode uint
	HttpResponse   string
	ContentType    string
	Content        string
}

type PrefetchSettings struct {
	Name      string
	Statement string
	Type      string
	Priority  int
}

type Service struct {
	Domain_name    string `json:"domain_name"`
	Service_id     string `json:"service_id"`
	Active_version int    `json:"active_version"`
}

type Features struct {
	Features []string `json:"features"`
}

type Rule struct {
	Included []struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Accuracy interface{} `json:"accuracy"`
			Maturity interface{} `json:"maturity"`
			Message  string      `json:"message"`
			Revision string      `json:"revision"`
			Severity int         `json:"severity"`
			Version  interface{} `json:"version"`
			RuleID   string      `json:"rule_id"`
			Source   interface{} `json:"source"`
			Vcl      interface{} `json:"vcl"`
		} `json:"attributes"`
	} `json:"included"`
}

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

func getActiveVersion(client fastly.Client, serviceID, apiKey string, config tomlConfig) int {

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
		}
	}

	//check if we found an active version otherwise exit
	if activeVersion == 0 {
		Error.Println("Found no active version on the service..exiting")
		os.Exit(1)
	}

	//return active version
	return activeVersion
}
func cloneVersion(client fastly.Client, serviceID, apiKey string, config tomlConfig, activeVersion int) (bool, int) {

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

func prefetchCondition(client fastly.Client, serviceID string, version int, config tomlConfig) bool {

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

func responseObject(client fastly.Client, serviceID string, version int, config tomlConfig) bool {
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
		Status:      config.Response.HttpStatusCode,
		Response:    config.Response.HttpResponse,
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
func vclSnippet(serviceID, apiKey string, version int, config tomlConfig) bool {
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
	} else {
		Error.Println("Could not add dynamic VCL snippet Fastly_WAF_Snippet the response was: ", resp.String())
		return false
	}

}

func FastlySOCLogging(client fastly.Client, serviceID string, version int, config tomlConfig) bool {
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
	Info.Println("Created SOC request logging endpoint: " + config.Weblog.Name)

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
	Info.Println("Created SOC WAF logging endpoint: " + config.Waflog.Name)
	return true
}
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

func wafContainer(client fastly.Client, serviceID string, version int, config tomlConfig) (bool, string) {
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

func createOWASP(client fastly.Client, serviceID, wafID string, version int, config tomlConfig) bool {
	//add tagging logic

	owasp, err := client.GetOWASP(&fastly.GetOWASPInput{
		Service: serviceID,
		ID:      wafID,
	})

	if owasp.ID == "" {
		owasp, err = client.CreateOWASP(&fastly.CreateOWASPInput{
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
			XDDScoreThreshold:			   config.Owasp.XssScoreThreshold,
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
		Info.Println(" - XssScoreThreshold:", owasp.XDDScoreThreshold)
		Info.Println(" - TotalArgLength:", owasp.TotalArgLength)
		Info.Println(" - WarningAnomalyScore:", owasp.WarningAnomalyScore)

	} else {

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
			XDDScoreThreshold:			   config.Owasp.XssScoreThreshold,
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
		Info.Println(" - XssScoreThreshold:", owasp.XDDScoreThreshold)
		Info.Println(" - TotalArgLength:", owasp.TotalArgLength)
		Info.Println(" - WarningAnomalyScore:", owasp.WarningAnomalyScore)
		return true
	}
	return true
}

func DeleteLogsCall(client fastly.Client, serviceID, apiKey string, config tomlConfig, version int) bool {

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
func DeprovisionWAF(client fastly.Client, serviceID, apiKey string, config tomlConfig, version int) bool {
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
	} else {
		for index, waf := range wafs {

			//remove WAF SOC Logging
			result := DeleteLogsCall(client, serviceID, apiKey, config, version)
			Info.Printf("Deleting WAF #%v SOC Logging", index+1)
			if !result {
				Error.Print(err)
				return false
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
				Error.Println("Error with API call: " + apiCall)
				os.Exit(1)
			}

		}
		return true
	}

}
func provisionWAF(client fastly.Client, serviceID, apiKey string, config tomlConfig, version int) string {

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
	if FastlySOCLogging(client, serviceID, version, config) {
		Info.Println("successfully created SOC logging settings")
	} else {
		Error.Printf("Fatal issue creating SOC logging settings..")
		os.Exit(1)
	}

	return wafID
}

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

	if body.Service_id == "" {
		Error.Println("Could not find the service ID for domain: " + domain + " please make sure it exists")
		os.Exit(1)
	}

	Info.Println("Found service id: " + body.Service_id + " for domain: " + domain)

	return body.Service_id
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
	} else {
		Info.Printf("Config Version %v Valid, remember to activate it!", version)
		return true

	}
}

/*
func emergencyConfig() {

}

func sslConfig() {

}
*/

func tagsConfig(apiEndpoint, apiKey, serviceID, wafID string, client fastly.Client, config tomlConfig) {
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
		body := Rule{}
		json.Unmarshal([]byte(resp.String()), &body)

		if len(body.Included) == 0 {
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
			Info.Printf(action+" %d rule on the WAF for tag: "+tag, len(body.Included))
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

func rulesConfig(apiEndpoint, apiKey, serviceID, wafID string, client fastly.Client, config tomlConfig) {
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

func DefaultRuleDisabled(apiEndpoint, apiKey, serviceID, wafID string, client fastly.Client, config tomlConfig) {

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

func WithPXCondition(client fastly.Client, serviceID string, version int, config tomlConfig) bool {

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

func main() {

	domain := flag.String("domain", "", "[Required] Domain to Provision, you can use Service ID alternatively")
	serviceID := flag.String("serviceid", "", "[Required] Service ID to Provision")
	apiKey := flag.String("apikey", "", "[Required] API Key to use")
	apiEndpoint := flag.String("apiendpoint", "https://api.fastly.com", "Fastly API endpoint to use.")
	//emergency := flag.Bool("emergency", false, "is this an emergency provisioning..see [wiki link]")
	//ssl := flag.Bool("ssl", false, "turn on ssl for this domain..see [wiki link]")
	configFile := flag.String("config", "waflyctl.toml", "Location of configuration file for waflyctl.")

	//var blocklist string
	//flag.StringVar(&blocklist, "blocklist", "gcp,aws,azure,aws,TOR", "Which blocklist should we provisioned on block mode in a comma delimited fashion. Available choices are: [for look here]")

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
	fmt.Println("Fastly WAF Control Tool v1.20180508 #team-soc")

	//run init to get our logging configured
	var config tomlConfig
	config = Init(os.Stdout, os.Stdout, os.Stderr, *configFile)

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
	client, err := fastly.NewClient(*apiKey)
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
		if FastlySOCLogging(*client, *serviceID, version, config) {
			Info.Println("successfully created SOC logging settings")
		} else {
			Error.Printf("Fatal issue creating SOC logging settings..")
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

	Info.Printf("currently working with config version: %v. Note rule, OWASP and tag changes do not generate a new config version", activeVersion)
	wafs, err := client.ListWAFs(&fastly.ListWAFsInput{
		Service: *serviceID,
		Version: activeVersion,
	})

	if err != nil {
		Error.Fatal(err)
	}

	if len(wafs) != 0 {
		Warning.Println("WAF object already exists...skipping provisioning")
		//do rule adjustment here
		for index, waf := range wafs {

			//if no individual tags or rules are set via CLI run both actions
			switch {
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
