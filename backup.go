package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// Backup is a backup of the rule status for a WAF
type Backup struct {
	ServiceID string
	WAFID     string
	ID        string
	Updated   time.Time
	Disabled  []string
	Block     []string
	Log       []string
	Owasp     OWASPSettings
}

// backupConfig retrieves from the API and returns all rules, statuses,
// configuration set, and OWASP settings and saves them to a TOML file
// at the given path.
func backupConfig(apiep, apikey, sid, wid, bpath string) (int, error) {
	b, err := getBackupData(apiep, apikey, sid, wid)
	if err != nil {
		return 0, fmt.Errorf("Error while getting backup data. %s", err)
	}

	ib, err := writeBackupToTOMLFile(b, bpath)
	if err != nil {
		return 0, fmt.Errorf("Error while writing backup to disk at `%s`. %s", bpath, err)
	}

	return ib, nil
}

// writeBackupToTOMLFile serializes the given backup object to a file at the
// given path.
func writeBackupToTOMLFile(b *Backup, bpath string) (int, error) {

	// validate the output path
	d := filepath.Dir(bpath)
	if _, err := os.Stat(d); os.IsNotExist(err) {
		return 0, fmt.Errorf("Output path does not exist: %s", d)
	}

	// encode the backup to TOML
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(b); err != nil {
		return 0, err
	}

	// write to disk
	err := ioutil.WriteFile(bpath, buf.Bytes(), 0644)
	if err != nil {
		return 0, err
	}

	return buf.Len(), nil
}

// getBackupData retrieves from the API and returns all rules, statuses,
// configuration set, and OWASP settings in a backup structure.
func getBackupData(apiep, apikey, sid, wid string) (*Backup, error) {

	// retrieve the owasp settings
	var ow *OWASPSettings
	var grerr error
	var wg sync.WaitGroup

	// don't waste time, pull the OWASP settings async while the rules are
	// being retrieved.
	go func() {
		wg.Add(1)
		ow, grerr = GetOWASPSettings(apiep, apikey, sid, wid)
		wg.Done()
	}()

	// retrieve the rules
	rl, rb, rd, err := GetRules(apiep, apikey, sid, wid)
	if err != nil {
		return &Backup{}, fmt.Errorf("Error while getting rules: %s", err)
	}

	// extract sorted rule ID
	ll := ruleArrToSortedStringArr(rl)
	lb := ruleArrToSortedStringArr(rb)
	ld := ruleArrToSortedStringArr(rd)

	wg.Wait()

	// throw error if problem getting OWASP, but wait for the waitgroup to finish
	// because it's unreasonable to assume this will always be handled fatally by
	// the invoker.
	if grerr != nil {
		return &Backup{}, fmt.Errorf("Error while getting OWASP settings: %s", err)
	}

	// create a UID for the backup
	hasher := sha1.New()
	hasher.Write([]byte(sid + time.Now().String()))
	sha := hex.EncodeToString((hasher.Sum(nil)))

	// return the backup object
	return &Backup{
		ID:        sha,
		ServiceID: sid,
		WAFID:     wid,
		Disabled:  ld,
		Block:     lb,
		Log:       ll,
		Owasp:     *ow,
		Updated:   time.Now(),
	}, nil
}
