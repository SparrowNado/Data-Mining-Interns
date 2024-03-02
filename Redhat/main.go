package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"
)

type Redhat struct {
	ThreatSeverity string    `json:"threat_severity"`
	PublicDate     time.Time `json:"public_date"`
	Bugzilla       struct {
		Description string `json:"description"`
		ID          string `json:"id"`
		URL         string `json:"url"`
	} `json:"bugzilla"`
	Cvss3 struct {
		Cvss3BaseScore     string `json:"cvss3_base_score"`
		Cvss3ScoringVector string `json:"cvss3_scoring_vector"`
		Status             string `json:"status"`
	} `json:"cvss3"`
	Cwe          string   `json:"cwe"`
	Details      []string `json:"details"`
	PackageState []struct {
		ProductName string `json:"product_name"`
		FixState    string `json:"fix_state"`
		PackageName string `json:"package_name"`
		Cpe         string `json:"cpe"`
	} `json:"package_state"`
	UpstreamFix string   `json:"upstream_fix"`
	References  []string `json:"references"`
	Name        string   `json:"name"`
	Csaw        bool     `json:"csaw"`
}

type Vulnerability struct {
	CVE         string                 `json:"cve,omitempty"`
	Package     string                 `json:"package,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Identifiers []string               `json:"identifiers,omitempty"`
}

func main() {

	// path to JSON files
	directory := "../JSONS/REDHAT"
	vulns := make(map[string]Vulnerability)

	dir, err := os.Open(directory)
	if err != nil {
		panic(err)
	}

	defer dir.Close()

	files, err := dir.ReadDir(-1)
	if err != nil {
		panic(err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue // Skip directories
		}

		// Open the JSON file
		filepath := filepath.Join(directory, file.Name())
		jsonFile, err := os.Open(filepath)
		if err != nil {
			panic(err)
		}

		defer jsonFile.Close()

		// Read the JSON file into byte slice
		data, err := io.ReadAll(jsonFile)
		if err != nil {
			panic(err)
		}

		if !isValidRawData(data) {
			// fmt.Printf("Skipping file %s: No raw data found\n", file.Name())
			continue
		}

		var dataModel Redhat

		// Unmarshal the JSON data into the SUSE struct
		err = json.Unmarshal(data, &dataModel)
		if err != nil {
			panic(err)
		}

		processData(&dataModel, file.Name(), vulns)
	}

	outputFolder := "../OUTPUT/Redhat"
	if _, err := os.Stat(outputFolder); os.IsNotExist(err) {
		if err := os.Mkdir(outputFolder, 0755); err != nil {
			panic(err)
		}
	}

	compiledFilePath := filepath.Join(outputFolder, "Redhat_output.json")
	compiledFile, err := os.Create(compiledFilePath)
	if err != nil {
		panic(err)
	}

	defer compiledFile.Close()

	vulnsData, err := json.MarshalIndent(vulns, "", "    ")
	if err != nil {
		panic(err)
	}

	_, err = compiledFile.Write(vulnsData)
	if err != nil {
		panic(err)
	}

}

func processData(dataModel *Redhat, fileName string, vulns map[string]Vulnerability) {
	vuln := Vulnerability{
		CVE:         dataModel.Name,
		Package:     "",
		Metadata:    map[string]interface{}{"redhat_data": *dataModel},
		Identifiers: []string{dataModel.Name},
	}
	vulns[vuln.CVE] = vuln

}

func isValidRawData(data []byte) bool {
	return bytes.Contains(data, []byte("\"threat_severity\"")) && bytes.Contains(data, []byte("\"public_date\""))
}
