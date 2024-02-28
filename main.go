package main

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
)

type SUSE struct {
	XMLName        xml.Name `xml:"oval_definitions" json:"oval_definitions,omitempty"`
	SchemaLocation string   `xml:"schemaLocation,attr" json:"schemalocation,omitempty"`
	Xmlns          string   `xml:"xmlns,attr" json:"xmlns,omitempty"`
	Xsi            string   `xml:"xsi,attr" json:"xsi,omitempty"`
	Oval           string   `xml:"oval,attr" json:"oval,omitempty"`
	OvalDef        string   `xml:"oval-def,attr" json:"oval-def,omitempty"`
	Generator      struct {
		ProductName   string `xml:"product_name"`
		SchemaVersion string `xml:"schema_version"`
		Timestamp     string `xml:"timestamp"`
	} `xml:"generator" json:"generator,omitempty"`
	Definitions struct {
		Definition []struct {
			ID       string `xml:"id,attr" json:"id,omitempty"`
			Version  string `xml:"version,attr" json:"version,omitempty"`
			Class    string `xml:"class,attr" json:"class,omitempty"`
			Metadata struct {
				Title    string `xml:"title"`
				Affected struct {
					Family   string `xml:"family,attr" json:"family,omitempty"`
					Platform string `xml:"platform"`
				} `xml:"affected" json:"affected,omitempty"`
				Reference struct {
					RefID  string `xml:"ref_id,attr" json:"ref_id,omitempty"`
					RefURL string `xml:"ref_url,attr" json:"ref_url,omitempty"`
					Source string `xml:"source,attr" json:"source,omitempty"`
				} `xml:"reference" json:"reference,omitempty"`
				Description string `xml:"description"`
			} `xml:"metadata" json:"metadata,omitempty"`
			Criteria struct {
				Operator  string `xml:"operator,attr" json:"operator,omitempty"`
				Criterion []struct {
					TestRef string `xml:"test_ref,attr" json:"test_ref,omitempty"`
					Comment string `xml:"comment,attr" json:"comment,omitempty"`
				} `xml:"criterion" json:"criterion,omitempty"`
				Criteria []struct {
					Operator  string `xml:"operator,attr" json:"operator,omitempty"`
					Criterion []struct {
						TestRef string `xml:"test_ref,attr" json:"test_ref,omitempty"`
						Comment string `xml:"comment,attr" json:"comment,omitempty"`
					} `xml:"criterion" json:"criterion,omitempty"`
					Criteria struct {
						Operator  string `xml:"operator,attr" json:"operator,omitempty"`
						Criterion []struct {
							TestRef string `xml:"test_ref,attr" json:"test_ref,omitempty"`
							Comment string `xml:"comment,attr" json:"comment,omitempty"`
						} `xml:"criterion" json:"criterion,omitempty"`
					} `xml:"criteria" json:"criteria,omitempty"`
				} `xml:"criteria" json:"criteria,omitempty"`
			} `xml:"criteria" json:"criteria,omitempty"`
		} `xml:"definition" json:"definition,omitempty"`
	} `xml:"definitions" json:"definitions,omitempty"`
	Tests struct {
		RpminfoTest []struct {
			ID      string `xml:"id,attr" json:"id,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
			Comment string `xml:"comment,attr" json:"comment,omitempty"`
			Check   string `xml:"check,attr" json:"check,omitempty"`
			Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
			Object  struct {
				ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
			} `xml:"object" json:"object,omitempty"`
			State struct {
				StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
			} `xml:"state" json:"state,omitempty"`
		} `xml:"rpminfo_test" json:"rpminfo_test,omitempty"`
	} `xml:"tests" json:"tests,omitempty"`
	Objects struct {
		RpminfoObject []struct {
			ID      string `xml:"id,attr" json:"id,omitempty"`
			Version string `xml:"version,attr" json:"version,omitempty"`
			Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
			Name    string `xml:"name"`
		} `xml:"rpminfo_object" json:"rpminfo_object,omitempty"`
	} `xml:"objects" json:"objects,omitempty"`
	States struct {
		RpminfoState []struct {
			ID          string `xml:"id,attr" json:"id,omitempty"`
			AttrVersion string `xml:"version,attr" json:"version,omitempty"`
			Xmlns       string `xml:"xmlns,attr" json:"xmlns,omitempty"`
			Version     struct {
				Operation string `xml:"operation,attr" json:"operation,omitempty"`
			} `xml:"version" json:"version,omitempty"`
			Evr struct {
				Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
				Operation string `xml:"operation,attr" json:"operation,omitempty"`
			} `xml:"evr" json:"evr,omitempty"`
		} `xml:"rpminfo_state" json:"rpminfo_state,omitempty"`
	} `xml:"states" json:"states,omitempty"`
}

type Vulnerability struct {
	CVE         string                 `json:"cve,omitempty"`
	Package     string                 `json:"package,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Identifiers []string               `json:"identifiers,omitempty"`
}

func main() {

	// path to JSON files
	directory := "JSONS/SUSE"

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

		var dataModel SUSE

		// Unmarshal the JSON data into the SUSE struct
		err = json.Unmarshal([]byte(data), &dataModel)
		if err != nil {
			panic(err)
		}

		processData(&dataModel, file.Name(), vulns)
	}

	outputFolder := "Output"
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

	// compiledFile, err := os.Create("Output.json")
	// if err != nil {
	// 	panic(err)
	// }

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

func processData(dataModel *SUSE, fileName string, vulns map[string]Vulnerability) {
	for _, d := range dataModel.Definitions.Definition {
		vuln, ok := vulns[d.ID]
		if !ok {
			vuln = Vulnerability{}
		}

		metadata := make(map[string]interface{})
		vuln.CVE = d.Metadata.Title
		vuln.Package = d.Metadata.Affected.Platform
		vuln.Identifiers = append(vuln.Identifiers, d.ID)
		metadata[fileName] = d.Metadata
		vuln.Metadata = metadata
		vulns[d.ID] = vuln
	}
}
