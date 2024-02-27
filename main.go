package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Vulnerability struct {
	CVE         string                 `json:"cve,omitempty"`
	Package     string                 `json:"package,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Identifiers []string               `json:"identifiers,omitempty"`
}

func main() {
	// Process the JSONS directory recursively
	err := processDirectory("JSONS")
	if err != nil {
		panic(err)
	}
	fmt.Println("All files processed successfully.")
}

func processDirectory(dirPath string) error {
	// Open the directory
	dirEntries, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}

	// Process each entry in the directory
	for _, entry := range dirEntries {
		fullPath := filepath.Join(dirPath, entry.Name())
		if entry.IsDir() {
			// If it's a directory, recursively process it
			err := processDirectory(fullPath)
			if err != nil {
				return err
			}
		} else {
			// If it's a file, check if it's a .json file
			if filepath.Ext(entry.Name()) == ".json" {
				err := processJSON(fullPath)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func processJSON(filePath string) error {
	// Define SUSE struct locally within the function scope
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

	fmt.Printf("Processing file: %s\n", filePath)

	// Open the JSON file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file %s: %v", filePath, err)
	}
	defer file.Close()

	// Read the JSON file into a byte slice
	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("error reading file %s: %v", filePath, err)
	}

	var rawData SUSE

	// Unmarshal the JSON data into the SUSE struct
	err = json.Unmarshal(data, &rawData)
	if err != nil {
		return fmt.Errorf("error unmarshalling JSON from file %s: %v", filePath, err)
	}

	vulns := make(map[string]Vulnerability)

	// Process the vulnerability data
	for _, d := range rawData.Definitions.Definition {
		var vuln Vulnerability
		if existingVuln, ok := vulns[d.ID]; ok {
			// If vulnerability already exists, use existing data
			vuln = existingVuln
		}
		vuln.CVE = d.Metadata.Title
		vuln.Package = d.Metadata.Affected.Platform
		vuln.Identifiers = append(vuln.Identifiers, d.ID)
		metadata := make(map[string]interface{})
		metadata[filePath] = d.Metadata
		vuln.Metadata = metadata
		vulns[d.ID] = vuln
	}

	// Determine the output directory path
	outputDir := filepath.Join("OUTPUT", filepath.Dir(filePath))
	err = os.MkdirAll(outputDir, 0755)
	if err != nil {
		return fmt.Errorf("error creating output directory: %v", err)
	}

	// Extract the filename
	outputFileName := filepath.Base(filePath)

	// Construct the output file path
	outputFile := filepath.Join(outputDir, outputFileName)

	// Write the vulns to the output JSON file
	vulnsFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer vulnsFile.Close()

	vulnsData, err := json.MarshalIndent(vulns, "", "    ")
	if err != nil {
		return fmt.Errorf("error marshalling JSON: %v", err)
	}

	_, err = vulnsFile.Write(vulnsData)
	if err != nil {
		return fmt.Errorf("error writing to output file: %v", err)
	}

	fmt.Printf("Processed file: %s\n", filePath)
	return nil
}
