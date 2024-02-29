package main

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

type Oracle struct {
	XMLName        xml.Name `xml:"oval_definitions"`
	Xmlns          string   `xml:"xmlns,attr"`
	Oval           string   `xml:"oval,attr"`
	OvalDef        string   `xml:"oval-def,attr"`
	UnixDef        string   `xml:"unix-def,attr"`
	RedDef         string   `xml:"red-def,attr"`
	Xsi            string   `xml:"xsi,attr"`
	SchemaLocation string   `xml:"schemaLocation,attr"`
	Generator      struct {
		ProductName    string `xml:"product_name"`
		ProductVersion string `xml:"product_version"`
		SchemaVersion  string `xml:"schema_version"`
		Timestamp      string `xml:"timestamp"`
	} `xml:"generator"`
	Definitions struct {
		Definition struct {
			ID       string `xml:"id,attr"`
			Version  string `xml:"version,attr"`
			Class    string `xml:"class,attr"`
			Metadata struct {
				Title    string `xml:"title"`
				Affected struct {
					Family   string `xml:"family,attr"`
					Platform string `xml:"platform"`
				} `xml:"affected"`
				Reference struct {
					Source string `xml:"source,attr"`
					RefID  string `xml:"ref_id,attr"`
					RefURL string `xml:"ref_url,attr"`
				} `xml:"reference"`
				Description string `xml:"description"`
				Advisory    struct {
					Severity string `xml:"severity"`
					Rights   string `xml:"rights"`
					Issued   struct {
						Date string `xml:"date,attr"`
					} `xml:"issued"`
				} `xml:"advisory"`
			} `xml:"metadata"`
			Criteria struct {
				Operator  string `xml:"operator,attr"`
				Criterion struct {
					TestRef string `xml:"test_ref,attr"`
					Comment string `xml:"comment,attr"`
				} `xml:"criterion"`
				Criteria struct {
					Operator string `xml:"operator,attr"`
					Criteria []struct {
						Operator  string `xml:"operator,attr"`
						Criterion struct {
							TestRef string `xml:"test_ref,attr"`
							Comment string `xml:"comment,attr"`
						} `xml:"criterion"`
						Criteria struct {
							Operator string `xml:"operator,attr"`
							Criteria []struct {
								Operator  string `xml:"operator,attr"`
								Criterion []struct {
									TestRef string `xml:"test_ref,attr"`
									Comment string `xml:"comment,attr"`
								} `xml:"criterion"`
							} `xml:"criteria"`
						} `xml:"criteria"`
					} `xml:"criteria"`
				} `xml:"criteria"`
			} `xml:"criteria"`
		} `xml:"definition"`
	} `xml:"definitions"`
	Tests struct {
		RpminfoTest []struct {
			ID      string `xml:"id,attr"`
			Version string `xml:"version,attr"`
			Comment string `xml:"comment,attr"`
			Check   string `xml:"check,attr"`
			Xmlns   string `xml:"xmlns,attr"`
			Object  struct {
				ObjectRef string `xml:"object_ref,attr"`
			} `xml:"object"`
			State struct {
				StateRef string `xml:"state_ref,attr"`
			} `xml:"state"`
		} `xml:"rpminfo_test"`
	} `xml:"tests"`
	Objects struct {
		RpminfoObject []struct {
			Xmlns   string `xml:"xmlns,attr"`
			ID      string `xml:"id,attr"`
			Version string `xml:"version,attr"`
			Name    string `xml:"name"`
		} `xml:"rpminfo_object"`
	} `xml:"objects"`
	States struct {
		RpminfoState []struct {
			Xmlns          string `xml:"xmlns,attr"`
			ID             string `xml:"id,attr"`
			AttrVersion    string `xml:"version,attr"`
			SignatureKeyid struct {
				Operation string `xml:"operation,attr"`
			} `xml:"signature_keyid"`
			Version struct {
				Operation string `xml:"operation,attr"`
			} `xml:"version"`
			Arch struct {
				Operation string `xml:"operation,attr"`
			} `xml:"arch"`
			Evr struct {
				Datatype  string `xml:"datatype,attr"`
				Operation string `xml:"operation,attr"`
			} `xml:"evr"`
		} `xml:"rpminfo_state"`
	} `xml:"states"`
}

type Vulnerability struct {
	CVE         string                 `json:"cve,omitempty"`
	Package     string                 `json:"package,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Identifiers []string               `json:"identifiers,omitempty"`
}

func main() {

	// path to JSON files
	directory := "../JSONS/ORACLE"

	dir, err := os.Open(directory)
	if err != nil {
		panic(err)
	}

	defer dir.Close()

	files, err := dir.ReadDir(-1)
	if err != nil {
		panic(err)
	}

	vulns := make(map[string]Vulnerability)

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

		data = removeNewlines(data)

		var dataModel Oracle

		// Unmarshal the JSON data into the SUSE struct
		err = json.Unmarshal(data, &dataModel)
		if err != nil {
			panic(err)
		}

		processData(&dataModel, file.Name(), vulns)
	}

	outputFolder := "../OUTPUT/Oracle"
	if _, err := os.Stat(outputFolder); os.IsNotExist(err) {
		if err := os.Mkdir(outputFolder, 0755); err != nil {
			panic(err)
		}
	}

	compiledFilePath := filepath.Join(outputFolder, "Output.json")
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

func processData(dataModel *Oracle, fileName string, vulns map[string]Vulnerability) {
	d := dataModel.Definitions.Definition
	vuln, ok := vulns[d.ID]
	if !ok {
		vuln = Vulnerability{}
	}

	metadata := make(map[string]interface{})
	vuln.CVE = string(removeNewlines([]byte(d.Metadata.Title)))
	vuln.Package = d.Metadata.Affected.Platform
	vuln.Identifiers = append(vuln.Identifiers, d.ID)
	metadata[fileName] = d.Metadata
	vuln.Metadata = metadata
	vulns[d.ID] = vuln
}

func removeNewlines(data []byte) []byte {
	reg := regexp.MustCompile(`\n`)
	return reg.ReplaceAll(data, []byte(""))
}
