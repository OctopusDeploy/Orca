package remediator

import (
	"Orca/pkg/handlers"
	"context"
	"fmt"
	gitHubAPI "github.com/google/go-github/v33/github"
	"gopkg.in/go-playground/webhooks.v5/github"
)

func RemediateFromPush(pushPayload github.PushPayload, results []handlers.CommitScanResult, handlerContext handlers.HandlerContext) error {
	// Open a new issue
	var title string
	if len(results) > 1 {
		title = fmt.Sprintf("Potentially sensitive data found in %d commits", len(results))
	} else {
		title = "Potentially sensitive data found in a commit"
	}

	body := "Potentially sensitive data has recently been pushed to this repository.\n\n"

	for _, result := range results {
		body += fmt.Sprintf("Introduced in %s:\n", result.Commit)

		// Add dangerous files
		if len(result.FileMatches) > 0 {

			body += "Potentially sensitive files:\n"
			for _, dangerousFile := range result.FileMatches {
				body += fmt.Sprintf("- [%s](%s)\n", *dangerousFile.Path, *dangerousFile.URL)
			}

			body += "\n\n"
		}

		// Add content matches
		if len(result.ContentMatches) > 0 {

			body += "Files containing potentially sensitive data:\n"
			for _, contentMatch := range result.ContentMatches {

				body += fmt.Sprintf("### %s\n", *contentMatch.Path)
				for _, lineMatch := range contentMatch.LineMatches {

					// TODO: Add a buffer around the line for extra context
					body += fmt.Sprintf("%s#L%d\n", *contentMatch.URL, lineMatch.LineNumber)
				}
			}
		}
	}

	_, _, err := handlerContext.GitHubAPIClient.Issues.Create(
		context.Background(),
		pushPayload.Repository.Owner.Login,
		pushPayload.Repository.Name,
		&gitHubAPI.IssueRequest{
			Title:     &title,
			Body:      &body,
			Assignee:  &pushPayload.Pusher.Name,
		})
	if err != nil {
		return err
	}

	return nil
}