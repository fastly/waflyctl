package main

import (
	"fmt"
	"github.com/fastly/waflyctl/pkg/wafly"
	"github.com/sethvargo/go-fastly/fastly"
	"gopkg.in/alecthomas/kingpin.v2"
	"io"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"github.com/BurntSushi/toml"


)

var (
	//Info level logging
	Info *log.Logger

	//Warning level logging
	Warning *log.Logger

	//Error level logging
	Error *log.Logger

)

func homeDir() string {
	user, err := user.Current()
	if err != nil {
		return os.Getenv("HOME")
	}
	return user.HomeDir
}


func main() {

	var (
		// version number
		version = "dev"
		date    = "unknown"
	)

	var (
		app              = kingpin.New("waflyctl", "Fastly WAF Control Tool").Version(version)
		action           = app.Flag("action", "Action to take on the rules list and rule tags. Overwrites action defined in config file. One of: disabled, block, log.").Enum("disabled", "block", "log")
		apiEndpoint      = app.Flag("apiendpoint", "Fastly API endpoint to use.").Default("https://api.fastly.com").String()
		apiKey           = app.Flag("apikey", "API Key to use.").Envar("FASTLY_API_TOKEN").Required().String()
		backup           = app.Flag("backup", "Store a copy of the WAF configuration locally.").Bool()
		backupPath       = app.Flag("backup-path", "Location for the WAF configuration backup file.").Default(homeDir() + "/waflyctl-backup-<service-id>.toml").String()
		configFile       = app.Flag("config", "Location of configuration file for waflyctl.").Default(homeDir() + "/.waflyctl.toml").String()
		configurationSet = app.Flag("configuration-set", "Changes WAF configuration set to the provided one.").String()
		deprovision      = app.Flag("delete", "Remove a WAF configuration created with waflyctl.").Bool()
		deleteLogs       = app.Flag("delete-logs", "When set removes WAF logging configuration.").Bool()
		forceStatus      = app.Flag("force-status", "Force all rules (inc. disabled) to update for the given tag.").Bool()
		logOnly          = app.Flag("enable-logs-only", "Add logging configuration only to the service. No other changes will be made. Can be used together with --with-perimeterx").Bool()
		listAllRules     = app.Flag("list-all-rules", "List all rules available on the Fastly platform for a given configuration set.").PlaceHolder("CONFIGURATION-SET").String()
		listConfigSet    = app.Flag("list-configuration-sets", "List all configuration sets and their status.").Bool()
		listRules        = app.Flag("list-rules", "List current WAF rules and their status.").Bool()
		editOWASP        = app.Flag("owasp", "Edit the OWASP object base on the settings in the configuration file.").Bool()
		provision        = app.Flag("provision", "Provision a new WAF or update an existing one.").Bool()
		publishers       = app.Flag("publisher", "Which rule publisher to use in a comma delimited fashion. Overwrites publisher defined in config file. Choices are: owasp, trustwave, fastly").String()
		rules            = app.Flag("rules", "Which rules to apply action on in a comma delimited fashion. Overwrites ruleid defined in config file. Example: 1010010,931100,931110.").String()
		serviceID        = app.Flag("serviceid", "Service ID to Provision.").Required().String()
		status           = app.Flag("status", "Disable or Enable the WAF. A disabled WAF will not block any traffic. In addition disabling a WAF does not change rule statuses on its configure policy. One of: disable, enable.").Enum("disable", "enable")
		tags             = app.Flag("tags", "Which rules tags to add to the ruleset in a comma delimited fashion. Overwrites tags defined in config file. Example: wordpress,language-php,drupal.").String()
		weblogExpiry     = app.Flag("web-log-expiry", "The default expiry of the web-log condition, expressed in days from the current date-time.").Default("-1").Int()
		withPX           = app.Flag("with-perimeterx", "Enable if the customer has PerimeterX enabled on the service as well as WAF. Helps fix null value logging.").Bool()
		withShielding    = app.Flag("with-shielding", "Enable if the customer has shielding enabled on the service. Helps fix multiple events with duplicate request IDs.").Bool()
	)


	kingpin.MustParse(app.Parse(os.Args[1:]))

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

	fmt.Println("Fastly WAF Control Tool version: " + version + " built on " + date)

	//run init to get our logging configured
	config := Init(*configFile)

	config.APIEndpoint = *apiEndpoint

	//check if rule action was set on CLI
	if *action != "" {
		config.Action = *action
		Info.Println("using rule action set by CLI: ", *action)
	}

	//check status rule action was set on CLI
	if *status != "" {
		Info.Println("using rule status set by CLI: ", *status)
	}

	//if rules are passed via CLI parse them and replace config parameters
	if *rules != "" {
		Info.Println("using rule IDS set by CLI:")
		ruleIDs := strings.Split(*rules, ",")
		for _, id := range ruleIDs {
			//cast IDs from string to int
			i, _ := strconv.ParseInt(id, 10, 32)
			Info.Println("- ruleID:", id)
			config.Rules = append(config.Rules, i)

		}
	}

	//if rule tags are passed via CLI parse them and replace config parameters
	if *tags != "" {
		Info.Println("using tags set by CLI:")
		tags := strings.Split(*tags, ",")
		for _, tag := range tags {
			Info.Println(" - tag name: ", tag)
			config.Tags = append(config.Tags, tag)
		}
	}

	//if rule publisher is passed via CLI parse them and replace config parameters
	if *publishers != "" {
		Info.Println("using publisher set by CLI:")
		publishers := strings.Split(*publishers, ",")
		for _, publisher := range publishers {
			Info.Println(" - publisher name: ", publisher)
			config.Publisher = append(config.Publisher, publisher)
		}
	}

	//if log expiry is passed through CLI, override config file
	if *weblogExpiry >= 0 {
		Info.Println("using web log expiry set by CLI:", *weblogExpiry)
		config.Weblog.Expiry = uint(*weblogExpiry)
	}

	//create Fastly client
	client, err := fastly.NewClientForEndpoint(*apiKey, config.APIEndpoint)
	if err != nil {
		Error.Fatal(err)
	}

	//get currently activeVersion to be used
	activeVersion := wafly.GetActiveVersion(*client, *serviceID)

	// add logs only to a service
	if *logOnly {

		Info.Println("Adding logging endpoints only")

		version := wafly.CloneVersion(*client, *serviceID, activeVersion)

		//create VCL Snippet
		wafly.VclSnippet(*client, *serviceID, config, version)

		//set logging parameters
		wafly.FastlyLogging(*client, *serviceID, config, version)

		//configure any logging conditions
		wafly.AddLoggingCondition(*client, *serviceID, version, config, *withShielding, *withPX)

		//validate the config
		wafly.ValidateVersion(*client, *serviceID, version)
		Info.Println("Completed")
		os.Exit(0)

	}
	// check if is a de-provisioning call
	if *deprovision {
		version := wafly.CloneVersion(*client, *serviceID, activeVersion)

		result := wafly.DeprovisionWAF(*client, *serviceID, *apiKey, config, version)
		if result {
			Info.Printf("Successfully deleted WAF on Service ID %s. Do not forget to activate version %v!\n", *serviceID, version)
			Info.Println("Completed")
			os.Exit(0)
		} else {
			Error.Printf("Failed to delete WAF on Service ID %s..see above for details\n", *serviceID)
			Info.Println("Completed")
			os.Exit(1)
		}
	}

	// check if is a delete logs parameter was called
	if *deleteLogs {
		version := wafly.CloneVersion(*client, *serviceID, activeVersion)

		//delete the logs
		result := wafly.DeleteLogsCall(*client, *serviceID, config, version)

		if result {
			Info.Printf("Successfully deleted logging endpint %s and %s in Service ID %s. Remember to activate version %v!\n", config.Weblog.Name, config.Waflog.Name, *serviceID, version)
			Info.Println("Completed")
			os.Exit(0)
		} else {
			Error.Printf("Failed to delete logging endpoints on Service ID %s..see above for details\n", *serviceID)
			Info.Println("Completed")
			os.Exit(1)
		}
	}

	Info.Printf("currently working with config version: %v.\n", activeVersion)
	Warning.Println("Publisher, Rules, OWASP Settings and Tags changes are versionless actions and thus do not generate a new config version")
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
			case *listConfigSet:
				Info.Println("Listing all configuration sets")
				wafly.GetConfigurationSets(config.APIEndpoint, *apiKey)
				Info.Println("Completed")
				os.Exit(0)

			//list waf rules
			case *listRules:
				Info.Printf("Listing all rules for WAF ID: %s\n", waf.ID)
				wafly.GetRules(config.APIEndpoint, *apiKey, *serviceID, waf.ID)
				Info.Println("Completed")
				os.Exit(0)

			//list all rules for a given configset
			case *listAllRules != "":
				Info.Printf("Listing all rules under configuration set ID: %s\n", *listAllRules)
				configID := *listAllRules
				wafly.GetAllRules(config.APIEndpoint, *apiKey, configID)
				Info.Println("Completed")
				os.Exit(0)

			//change a configuration set
			case *configurationSet != "":
				Info.Printf("Changing Configuration Set to: %s\n", *configurationSet)
				configID := *configurationSet
				wafly.SetConfigurationSet(waf.ID, configID, *client)
				Info.Println("Completed")
				os.Exit(0)

			case *status != "":
				Info.Println("Changing WAF Status")
				//rule management
				wafly.ChangeStatus(config.APIEndpoint, *apiKey, waf.ID, *status)
				Info.Println("Completed")
				os.Exit(0)

			case *tags != "":
				Info.Println("Editing Tags")
				//tags management
				wafly.TagsConfig(config.APIEndpoint, *apiKey, *serviceID, waf.ID, config, *forceStatus)

				//patch ruleset
				if wafly.PatchRules(*serviceID, waf.ID, *client) {
					Info.Println("Rule set successfully patched")

				} else {
					Error.Println("Issue patching ruleset see above error..")
				}

			case *publishers != "":
				Info.Println("Editing Publishers")
				//Publisher management
				wafly.PublisherConfig(config.APIEndpoint, *apiKey, *serviceID, waf.ID, config)

				//patch ruleset
				if wafly.PatchRules(*serviceID, waf.ID, *client) {
					Info.Println("Rule set successfully patched")

				} else {
					Error.Println("Issue patching ruleset see above error..")
				}

			case *rules != "":
				Info.Println("Editing Rules")
				//rule management
				wafly.RulesConfig(config.APIEndpoint, *apiKey, *serviceID, waf.ID, config)

				//patch ruleset
				if wafly.PatchRules(*serviceID, waf.ID, *client) {
					Info.Println("Rule set successfully patched")

				} else {
					Error.Println("Issue patching ruleset see above error..")
				}

			case *editOWASP:
				Info.Printf("Editing OWASP settings for WAF #%v\n", index+1)
				wafly.CreateOWASP(*client, *serviceID, config, waf.ID)

				//patch ruleset
				if wafly.PatchRules(*serviceID, waf.ID, *client) {
					Info.Println("Rule set successfully patched")

				} else {
					Error.Println("Issue patching ruleset see above error..")
				}

			case *withPX || *withShielding:
				Info.Println("WAF enabled with Shielding or PerimeterX, setting logging conditions")
				version := wafly.CloneVersion(*client, *serviceID, activeVersion)
				wafly.AddLoggingCondition(*client, *serviceID, version, config, *withShielding, *withPX)

			//back up WAF rules locally
			case *backup:
				Info.Println("Backing up WAF configuration")

				bp := strings.Replace(*backupPath, "<service-id>", *serviceID, -1)

				if !wafly.BackupConfig(*apiEndpoint, *apiKey, *serviceID, waf.ID, *client, bp) {
					os.Exit(1)
				}

			case *provision:
				//tags management
				wafly.TagsConfig(config.APIEndpoint, *apiKey, *serviceID, waf.ID, config, *forceStatus)
				//rule management
				wafly.RulesConfig(config.APIEndpoint, *apiKey, *serviceID, waf.ID, config)
				//publisher management
				wafly.PublisherConfig(config.APIEndpoint, *apiKey, *serviceID, waf.ID, config)
				//OWASP
				wafly.CreateOWASP(*client, *serviceID, config, waf.ID)

				//patch ruleset
				if wafly.PatchRules(*serviceID, waf.ID, *client) {
					Info.Println("Rule set successfully patched")

				} else {
					Error.Println("Issue patching ruleset see above error..")
				}

			default:
				Error.Println("Nothing to do. Exiting")
				os.Exit(1)
			}

			//validate the config
			wafly.ValidateVersion(*client, *serviceID, activeVersion)
			Info.Println("Completed")
			os.Exit(0)
		}

	} else if *provision {
		Warning.Printf("Provisioning a new WAF on Service ID: %s\n", *serviceID)

		//clone current version
		version := wafly.CloneVersion(*client, *serviceID, activeVersion)

		//provision a new WAF service
		wafID := wafly.ProvisionWAF(*client, *serviceID, config, version)

		//publisher management
		wafly.PublisherConfig(config.APIEndpoint, *apiKey, *serviceID, wafID, config)

		//tags management
		wafly.TagsConfig(config.APIEndpoint, *apiKey, *serviceID, wafID, config, *forceStatus)

		//rule management
		wafly.RulesConfig(config.APIEndpoint, *apiKey, *serviceID, wafID, config)

		//Default Disabled
		wafly.DefaultRuleDisabled(config.APIEndpoint, *apiKey, *serviceID, wafID, config)

		//Add logging conditions
		wafly.AddLoggingCondition(*client, *serviceID, version, config, *withShielding, *withPX)

		latest, err := client.LatestVersion(&fastly.LatestVersionInput{
			Service: *serviceID,
		})
		if err != nil {
			Error.Fatal(err)
		}

		//patch ruleset
		if wafly.PatchRules(*serviceID, wafID, *client) {
			Info.Println("Rule set successfully patched")

		} else {
			Error.Println("Issue patching ruleset see above error..")
		}

		//validate the config
		wafly.ValidateVersion(*client, *serviceID, latest.Number)
		Info.Println("Completed")
		os.Exit(0)
	} else {
		Error.Println("Nothing to do. Exiting")
		os.Exit(1)
	}

}

//Init function starts our logger
func Init(configFile string) wafly.TOMLConfig {

	//load configs
	var config wafly.TOMLConfig
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
		log.Fatalln("Failed to open log file", config.Logpath, ":", err)
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

	wafly.Info = Info
	wafly.Warning = Warning
	wafly.Error = Error

	return config
}
