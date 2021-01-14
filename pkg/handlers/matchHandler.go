package handlers

import (
	"Orca/pkg/scanning"
	"context"
	"fmt"
	"github.com/google/go-github/v33/github"
	"github.com/rs/zerolog/log"
)

type MatchHandler struct {
	GitHubApiClient *github.Client
}

func NewMatchHandler(gitHubApiClient *github.Client) *MatchHandler {
	return &MatchHandler{
		GitHubApiClient: gitHubApiClient,
	}
}

func (matchHandler *MatchHandler) HandleMatchesFromPush(
	pushPayload *github.PushEvent,
	results []scanning.CommitScanResult) error {

	// Open a new issue
	title, body := BuildMessage(results)
	log.Info().Msgf("Opening a new issue \"%s\"\n", title)
	issue, _, err := matchHandler.GitHubApiClient.Issues.Create(
		context.Background(),
		*pushPayload.Repo.Owner.Login,
		*pushPayload.Repo.Name,
		&github.IssueRequest{
			Title:    &title,
			Body:     &body,
			Assignee: pushPayload.Pusher.Name,
		})
	if err != nil {
		return err
	}

	log.Info().Msgf("Issue #%d opened\n", issue.Number)

	return nil
}

func (matchHandler *MatchHandler) HandleMatchesFromIssue(
	issue *github.IssuesEvent,
	result *scanning.IssueScanResult) error {

	log.Info().Msgf("Redacting matches from #%d\n", issue.Issue.Number)
	newBody := redactMatchesFromContent(*issue.Issue.Body, result.Matches, '*')

	// Replace the issue body with the new body with redacted matches
	_, _, err := matchHandler.GitHubApiClient.Issues.Edit(
		context.Background(),
		*issue.Issue.Repository.Owner.Login,
		*issue.Issue.Repository.Name,
		*issue.Issue.Number,
		&github.IssueRequest{
			Body: &newBody,
		})
	if err != nil {
		return err
	}
	log.Info().Msgf("Matches from #%d redacted\n", issue.Issue.Number)

	return nil
}

func (matchHandler *MatchHandler) HandleMatchesFromIssueComment(
	issue *github.IssueCommentEvent,
	result *scanning.IssueScanResult) error {

	log.Info().Msgf("Redacting matches from #%d (comment %d)\n", issue.Issue.Number, issue.Comment.ID)
	newBody := redactMatchesFromContent(*issue.Comment.Body, result.Matches, '*')

	// Replace the issue body with the new body with redacted matches
	_, _, err := matchHandler.GitHubApiClient.Issues.EditComment(
		context.Background(),
		*issue.Repo.Owner.Login,
		*issue.Repo.Name,
		*issue.Comment.ID,
		&github.IssueComment{
			Body: &newBody,
		})
	if err != nil {
		return err
	}
	log.Info().Msgf("Matches from #%d (comment %d) redacted\n", issue.Issue.Number, issue.Comment.ID)

	return nil
}

func (matchHandler *MatchHandler) HandleMatchesFromPullRequest(
	request *github.PullRequestEvent,
	result *scanning.PullRequestScanResult) error {

	log.Info().Msgf("Redacting matches from #%d\n", request.PullRequest.Number)

	newBody := redactMatchesFromContent(*request.PullRequest.Body, result.Matches, '*')

	// Replace the pull request body with new body with redacted matches
	_, _, err := matchHandler.GitHubApiClient.PullRequests.Edit(
		context.Background(),
		*request.Repo.Owner.Login,
		*request.Repo.Name,
		*request.PullRequest.Number,
		&github.PullRequest{
			Body: &newBody,
		})
	if err != nil {
		return err
	}
	log.Info().Msgf("Matches from #%d redacted\n", request.PullRequest.Number)

	return nil
}

func (matchHandler *MatchHandler) HandleMatchesFromPullRequestReview(
	request *github.PullRequestReviewEvent,
	result *scanning.PullRequestReviewScanResult) error {

	log.Info().Msgf("Redacting matches from #%d (review %d)\n", request.PullRequest.Number, request.Review.ID)

	newBody := redactMatchesFromContent(*request.Review.Body, result.Matches, '*')

	// Replace the pull request body with new body with redacted matches
	_, _, err := matchHandler.GitHubApiClient.PullRequests.UpdateReview(
		context.Background(),
		*request.Repo.Owner.Login,
		*request.Repo.Name,
		*request.PullRequest.Number,
		*request.Review.ID,
		newBody)
	if err != nil {
		return err
	}
	log.Info().Msgf("Matches from #%d redacted (review %d)\n", request.PullRequest.Number, request.Review.ID)

	return nil
}

func (matchHandler *MatchHandler) HandleMatchesFromPullRequestReviewComment(
	request *github.PullRequestReviewCommentEvent,
	result *scanning.PullRequestReviewCommentScanResult) error {

	log.Info().Msgf(
		"Redacting matches from #%d (review %d, comment %d)\n",
		request.PullRequest.Number,
		request.Comment.InReplyTo,
		request.Comment.ID)

	newBody := redactMatchesFromContent(*request.Comment.Body, result.Matches, '*')

	// Replace the pull request body with new body with redacted matches
	_, _, err := matchHandler.GitHubApiClient.PullRequests.EditComment(
		context.Background(),
		*request.Repo.Owner.Login,
		*request.Repo.Name,
		*request.Comment.ID,
		&github.PullRequestComment{
			Body: &newBody,
		})
	if err != nil {
		return err
	}
	log.Info().Msgf(
		"Matches from #%d redacted (review %d, comment %d)\n",
		request.PullRequest.Number,
		request.Comment.InReplyTo,
		request.Comment.ID)

	return nil
}

func redactMatchesFromContent(content string, lineMatches []scanning.LineMatch, replacementCharacter rune) string {

	contentRunes := []rune(content)
	for _, lineMatch := range lineMatches {
		lineNumber := lineMatch.LineNumber

		// Skip to the specified line number
		currentLineNumber := 1
		indexInLine := 0
		for i, ch := range contentRunes {

			// Counting each new line we find to find the line number
			startOfNewLine := false
			if ch == '\n' {
				currentLineNumber++
				indexInLine = 0
				startOfNewLine = true
			}

			// Make sure we're on the right line
			if currentLineNumber == lineNumber {

				// Check if the current index on the line is within the range of one of the matches
				if indexInLine >= lineMatch.StartIndex && indexInLine < lineMatch.EndIndex {
					contentRunes[i] = replacementCharacter
				}
			}

			// Don't increment if we just decided we're on a new line
			if !startOfNewLine {
				indexInLine++
			}
		}
	}

	contentString := string(contentRunes)

	return contentString
}

func BuildMessage(results []scanning.CommitScanResult) (string, string) {
	var title string
	var body string

	if len(results) > 1 {
		title = fmt.Sprintf("Potentially sensitive data found in %d commits.", len(results))
	} else {
		title = "Potentially sensitive data found in a commit."
	}

	if len(results) > 1 {
		body = fmt.Sprintf("Potentially sensitive data has been found in %d commits.", len(results))
	} else {
		body = "Potentially sensitive data has been found in a commit."
	}

	body += "\n\n"

	for _, result := range results {

		// Add matches
		if len(result.Matches) > 0 {

			body += fmt.Sprintf("Introduced in %s:\n", result.Commit)
			for _, match := range result.Matches {

				// Todo: Group lines which are directly below each other into one permalink (e.g. #L2-L4)
				body += fmt.Sprintf("#### %s:\n", match.Kind)
				body += fmt.Sprintf("`%s`\n", match.Path)
				body += fmt.Sprintf("%s#L%d\n", match.PermalinkURL, match.LineNumber)
			}

			body += "\n\n"
		}
	}

	return title, body
}
