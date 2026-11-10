// Run with: go run ./reference.go ./v1.json
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/template"
)

type fixtureSet struct {
	Version int       `json:"version"`
	Cases   []fixture `json:"cases"`
}

type fixture struct {
	Name       string         `json:"name"`
	Template   string         `json:"template"`
	Data       map[string]any `json:"data"`
	Output     *string        `json:"output"`
	Error      *string        `json:"error"`
	Diagnostic *string        `json:"diagnostic"`
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: go run ./reference.go ./v1.json")
	}
	contents, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var fixtures fixtureSet
	if err := json.Unmarshal(contents, &fixtures); err != nil {
		panic(err)
	}
	if fixtures.Version != 1 {
		panic(fmt.Sprintf("unsupported fixture format version: %d", fixtures.Version))
	}
	// Keep the safe V1 default helper fixed at two arguments. The upstream
	// implementation is variadic, but that difference is not part of V1.
	functions := template.FuncMap{
		"default": func(fallback, value any) any {
			if emptyValue(value) {
				return fallback
			}
			return value
		},
		"quote":    func(value any) string { return strconv.Quote(fmt.Sprint(value)) },
		"trim":     func(value any) string { return strings.TrimSpace(fmt.Sprint(value)) },
		"lower":    func(value any) string { return strings.ToLower(fmt.Sprint(value)) },
		"upper":    func(value any) string { return strings.ToUpper(fmt.Sprint(value)) },
		"contains": func(needle, value any) bool { return strings.Contains(fmt.Sprint(value), fmt.Sprint(needle)) },
	}
	for _, fixture := range fixtures.Cases {
		validateFixture(fixture)
		err := validateV1Template(fixture.Template)
		var output strings.Builder
		if err == nil {
			var parsed *template.Template
			parsed, err = template.New(fixture.Name).Funcs(functions).Option("missingkey=error").Parse(fixture.Template)
			if err == nil {
				err = parsed.Execute(&output, fixture.Data)
			}
			if err == nil && fixture.Output != nil && output.String() != *fixture.Output {
				panic(fmt.Sprintf("fixture %s: got %q, want %q", fixture.Name, output.String(), *fixture.Output))
			}
		}

		if fixture.Error != nil {
			if err == nil {
				panic(fmt.Sprintf("fixture %s: expected error %q, got success", fixture.Name, *fixture.Error))
			}
			continue
		}
		if err != nil {
			panic(fmt.Sprintf("fixture %s: %v", fixture.Name, err))
		}
	}
}

func emptyValue(value any) bool {
	switch value := value.(type) {
	case string:
		return value == ""
	case bool:
		return !value
	case []any:
		return len(value) == 0
	case map[string]any:
		return len(value) == 0
	default:
		return false
	}
}

// validateV1Template applies the one intentional V1 grammar restriction that
// differs from text/template: character literals are not part of the safe
// subset. All other syntax is left to Go's parser and executor.
func validateV1Template(source string) error {
	position := 0
	for position < len(source) {
		relativeStart := strings.Index(source[position:], "{{")
		if relativeStart < 0 {
			return nil
		}
		position += relativeStart + 2

		var quote byte
		escaped := false
		comment := false
		for position < len(source) {
			if comment {
				if strings.HasPrefix(source[position:], "*/") {
					comment = false
					position += 2
				} else {
					position++
				}
				continue
			}
			if quote != 0 {
				if quote == '`' {
					if source[position] == '`' {
						quote = 0
					}
				} else if escaped {
					escaped = false
				} else if source[position] == '\\' {
					escaped = true
				} else if source[position] == quote {
					quote = 0
				}
				position++
				continue
			}

			if strings.HasPrefix(source[position:], "/*") {
				comment = true
				position += 2
				continue
			}
			if source[position] == '\'' {
				return fmt.Errorf("character literals are not supported")
			}
			if source[position] == '"' || source[position] == '`' {
				quote = source[position]
			} else if strings.HasPrefix(source[position:], "}}") {
				position += 2
				break
			}
			position++
		}
	}
	return nil
}

func validateFixture(fixture fixture) {
	hasOutput := fixture.Output != nil
	hasError := fixture.Error != nil
	if hasOutput == hasError {
		panic(fmt.Sprintf("fixture %s must specify exactly one output or error", fixture.Name))
	}
	if hasError && strings.TrimSpace(*fixture.Error) == "" {
		panic(fmt.Sprintf("fixture %s must specify a meaningful expected error", fixture.Name))
	}
	if fixture.Diagnostic != nil && strings.TrimSpace(*fixture.Diagnostic) == "" {
		panic(fmt.Sprintf("fixture %s must specify a non-empty diagnostic", fixture.Name))
	}
	if hasOutput && fixture.Diagnostic != nil {
		panic(fmt.Sprintf("fixture %s must not specify a diagnostic for a successful result", fixture.Name))
	}
}
