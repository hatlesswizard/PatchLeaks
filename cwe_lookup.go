package main

import (
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	cweLookupOnce sync.Once
	cweLookupMap  map[string]string
	cweLookupErr  error
)

func getCWEDataPath() string {
	return filepath.Join("static", "cwe", "cwe.xml")
}

func loadCWEMap() {
	cweLookupOnce.Do(func() {
		cweLookupMap = make(map[string]string)
		filePath := getCWEDataPath()
		f, err := os.Open(filePath)
		if err != nil {
			cweLookupErr = err
			return
		}
		defer f.Close()

		decoder := xml.NewDecoder(f)
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				cweLookupErr = err
				return
			}
			switch elem := token.(type) {
			case xml.StartElement:
				if elem.Name.Local != "Weakness" {
					continue
				}
				var id, name string
				for _, attr := range elem.Attr {
					switch attr.Name.Local {
					case "ID":
						id = attr.Value
					case "Name":
						name = attr.Value
					}
				}
				if id == "" || name == "" {
					continue
				}
				norm := normalizeCWEID(id)
				if norm == "" {
					continue
				}
				cweLookupMap[norm] = strings.TrimSpace(name)
			}
		}
	})
}

func GetCWEName(id string) (string, bool) {
	loadCWEMap()
	if cweLookupErr != nil {
		return "", false
	}
	norm := normalizeCWEID(id)
	if norm == "" {
		return "", false
	}
	name, ok := cweLookupMap[norm]
	return name, ok
}

func normalizeCWEID(id string) string {
	trimmed := strings.TrimSpace(strings.ToUpper(id))
	trimmed = strings.TrimPrefix(trimmed, "CWE-")
	trimmed = strings.TrimLeft(trimmed, "0")
	if trimmed == "" {
		return ""
	}
	for len(trimmed) > 1 && trimmed[0] == '0' {
		trimmed = trimmed[1:]
	}
	return trimmed
}
