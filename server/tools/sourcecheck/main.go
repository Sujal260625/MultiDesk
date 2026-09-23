// sourcecheck parses all project Go sources without fetching optional modules.
package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	count := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if _, e := parser.ParseFile(token.NewFileSet(), path, nil, parser.AllErrors); e != nil {
			return e
		}
		count++
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Parsed %d Go source files successfully. This does not replace compilation or tests.\n", count)
}
