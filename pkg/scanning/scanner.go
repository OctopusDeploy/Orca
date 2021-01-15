package scanning

import (
	"Orca/pkg/caching"
	"errors"
	"fmt"
	"github.com/google/go-github/v33/github"
	"github.com/rs/zerolog/log"
	"strings"
)

type FileContentMatch struct {
	caching.File
	LineMatch
}

type LineMatch struct {
	LineNumber int
	Match
}

type Match struct {
	StartIndex int
	EndIndex   int
	value      string
	Kind       string
	Resolved   bool
}

type Scanner struct {
	Patterns []SearchPattern
}

func NewScanner(patternStore *PatternStore) (*Scanner, error) {

	patterns, err := (*patternStore).GetPatterns()
	if err != nil {
		return nil, err
	}

	scanner := &Scanner{
		Patterns: patterns,
	}

	return scanner, nil
}

func (scanner *Scanner) CheckFileContentFromQueries(
	githubClient *github.Client,
	fileQueries []caching.GitHubFileQuery) ([]CommitScanResult, error) {

	var commitScanResults []CommitScanResult
	for _, fileQuery := range fileQueries {

		// NOTE: ListCommits does not include any references to which files were changed (commit.Files is always nil),
		//	so we need to send another request specifically for the commit
		// TODO: Find a way around this to prevent getting rate limited
		commitScanResult := CommitScanResult{Commit: fileQuery.CommitSHA}

		// If the file was removed, then mark any previous matches as resolved
		if fileQuery.Status == caching.FileRemoved {
			for i, previousScanResult := range commitScanResults {
				for j, previousFileMatch := range previousScanResult.Matches {
					if previousFileMatch.Path == fileQuery.FileName {
						commitScanResults[i].Matches[j].Resolved = true
					}
				}
			}

			continue
		}

		// Can only scan contents of added and modified files
		if fileQuery.Status != caching.FileAdded && fileQuery.Status != caching.FileModified {
			continue
		}

		log.Debug().Msgf("Checking %s from %s", fileQuery.FileName, fileQuery.CommitSHA)

		fileContentMatches, err := scanner.CheckFileContentFromQuery(githubClient, fileQuery)
		if err != nil {
			return nil, err
		}

		if len(fileContentMatches) > 0 {

			// Ignore previously known matches
			for _, fileContentMatch := range fileContentMatches {
				if !MatchIsKnown(getMatches(commitScanResults), fileContentMatch) {
					commitScanResult.Matches = append(commitScanResult.Matches, fileContentMatch)
				}
			}

		} else {

			// No matches found, previous matches in this file should be resolved
			for i, previousScanResult := range commitScanResults {
				for j, previousFileMatch := range previousScanResult.Matches {
					if previousFileMatch.Path == fileQuery.FileName {
						commitScanResults[i].Matches[j].Resolved = true
					}
				}
			}
		}

		if commitScanResult.HasMatches() {
			commitScanResults = append(commitScanResults, commitScanResult)
		}
	}

	return commitScanResults, nil
}

func (scanner *Scanner) CheckFileContentFromQuery(
	githubClient *github.Client,
	fileQuery caching.GitHubFileQuery) ([]FileContentMatch, error) {

	// Can't check the Content of a deleted file, just error our here and save ourselves another HTTP request
	if fileQuery.Status == caching.FileRemoved {
		errMessage := fmt.Sprintf("cannot check Content of file \"%s\" as it was removed in the specified commit (%s)", fileQuery.FileName, fileQuery.CommitSHA)
		return nil, errors.New(errMessage)
	}

	file, err := caching.GetFile(fileQuery, githubClient)
	if err != nil {
		return nil, err
	}

	return scanner.CheckFileContent(file)
}

func (scanner *Scanner) CheckFileContent(file *caching.File) ([]FileContentMatch, error) {

	var result []FileContentMatch

	lineMatches, err := scanner.CheckContent(file.Content)
	if err != nil {
		return nil, err
	}

	if len(lineMatches) > 0 {
		for _, lineMatch := range lineMatches {
			fileMatch := FileContentMatch{
				File:      *file,
				LineMatch: lineMatch,
			}

			result = append(result, fileMatch)
		}
	}

	return result, nil
}

func (scanner *Scanner) CheckContent(content string) ([]LineMatch, error) {

	var result []LineMatch

	// Todo: Multi-line scan first, then single-line scan around any multi-line match ranges
	var lines = strings.Split(content, "\n")
	for i, line := range lines {
		lineNumber := i + 1
		matchesOnLine, err := scanner.scanLineForPatterns(line)
		if err != nil {
			return nil, err
		}

		// Todo: Another loop, any way around this?
		if len(matchesOnLine) > 0 {
			for _, matchOnLine := range matchesOnLine {
				lineMatch := LineMatch{
					LineNumber: lineNumber,
					Match:      matchOnLine,
				}

				result = append(result, lineMatch)
			}
		}
	}

	return result, nil
}

func (scanner *Scanner) scanLineForPatterns(line string) ([]Match, error) {
	var matches []Match
	for _, pattern := range scanner.Patterns {
		currentPatternMatches, err := scanLineForPattern(line, pattern)
		if err != nil {
			return nil, err
		}

		if len(currentPatternMatches) > 0 {
			matches = append(matches, currentPatternMatches...)
		}
	}

	return matches, nil
}

func scanLineForPattern(line string, pattern SearchPattern) ([]Match, error) {
	var matches []Match
	regex, err := pattern.GetRegexp()
	if err != nil {
		return nil, err
	}

	var regexMatches = regex.FindAllStringIndex(line, -1)
	for _, match := range regexMatches {
		var startIndex = match[0]
		var endIndex = match[1]
		value := line[startIndex:endIndex]

		// Ignore if the matched string is allowed to be excluded from checks
		if pattern.CanIgnore(value) {
			continue
		}

		matches = append(matches, Match{
			StartIndex: startIndex,
			EndIndex:   endIndex,
			value:      value,
			Kind:       pattern.Kind,
		})
	}

	return matches, nil
}

func getMatches(commitScanResults []CommitScanResult) []FileContentMatch {
	var result []FileContentMatch
	for _, commitScanResult := range commitScanResults {
		result = append(result, commitScanResult.Matches...)
	}

	return result
}

func MatchIsKnown(knownFileContentMatches []FileContentMatch, newFileContentMatch FileContentMatch) bool {
	for _, knownFileContentMatch := range knownFileContentMatches {
		if knownFileContentMatch.Path == newFileContentMatch.Path {
			if newFileContentMatch.value == knownFileContentMatch.value &&
				!knownFileContentMatch.Resolved {
				return true
			}
		}
	}

	return false
}
