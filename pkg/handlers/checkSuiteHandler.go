package handlers

import (
	"Orca/pkg/caching"
	"Orca/pkg/scanning"
	"context"
	"fmt"
	"github.com/google/go-github/v33/github"
	"github.com/rs/zerolog/log"
)

type checkRunStatus string
type checkRunConclusion string

const (
	checkRunStatusInProgress  checkRunStatus     = "in_progress"
	checkRunStatusCompleted   checkRunStatus     = "completed"
	checkRunConclusionSuccess checkRunConclusion = "success"
	checkRunConclusionSkipped checkRunConclusion = "skipped"
	checkRunConclusionFailure checkRunConclusion = "failure"
)

// BUG: This will trigger a failure even if the issue has been fixed in a more recent commit

func (handler *PayloadHandler) HandleCheckSuite(checkSuitePayload *github.CheckSuiteEvent) {
	log.Info().Msgf(
		"Handling check suite event from %s/%s (%d)",
		*checkSuitePayload.Repo.Owner.Login,
		*checkSuitePayload.Repo.Name,
		*checkSuitePayload.CheckSuite.ID)

	// Create a new Check Run
	log.Debug().Msg("Creating new check run")
	inProgressString := string(checkRunStatusInProgress)
	checkRun, _, err := handler.GitHubClient.Checks.CreateCheckRun(
		context.Background(),
		*checkSuitePayload.Repo.Owner.Login,
		*checkSuitePayload.Repo.Name,
		github.CreateCheckRunOptions{
			Name:    "Orca Checks",
			HeadSHA: *checkSuitePayload.CheckSuite.HeadSHA,
			Status:  &inProgressString,
		})
	if err != nil {
		log.Error().Err(err)
		return
	}
	log.Debug().Msgf("Check run %d created", checkRun.ID)

	// Bring over some of the properties we want to access later
	checkRun.CheckSuite.Repository = checkSuitePayload.Repo

	// Execute the check
	if len(checkSuitePayload.CheckSuite.PullRequests) > 0 {
		for _, pullRequest := range checkSuitePayload.CheckSuite.PullRequests {
			commits, _, err := handler.GitHubClient.PullRequests.ListCommits(
				context.Background(),
				*checkSuitePayload.Repo.Owner.Login,
				*checkSuitePayload.Repo.Name,
				*pullRequest.Number,
				nil)
			if err != nil {
				handler.handleFailure(
					checkRun,
					fmt.Sprintf("Failed to get commits from pull request #%d", pullRequest.Number),
					err)
				return
			}

			// Note: Timestamp not available in these commits for some reason (but they are in the Push event???)
			//	Have to assume the commits are in the correct order.

			// Get a list of commit SHAs
			var fileQueries []caching.GitHubFileQuery
			for _, commit := range commits {
				commitSha := commit.SHA

				// Todo: Files from commit not available in commit list, need another request...
				commitWithFiles, _, err := handler.GitHubClient.Repositories.GetCommit(
					context.Background(),
					*checkSuitePayload.Repo.Owner.Login,
					*checkSuitePayload.Repo.Name,
					*commitSha)
				if err != nil {
					handler.handleFailure(
						checkRun,
						fmt.Sprintf("Failed to get commit %s from pull request #%d", *commitSha, pullRequest.Number),
						err)
					return
				}

				for _, file := range commitWithFiles.Files {
					var fileStatus caching.FileState
					switch *file.Status {
					case "added":
						fileStatus = caching.FileAdded
					case "modified":
						fileStatus = caching.FileModified
					case "removed":
						fileStatus = caching.FileRemoved
					}

					fileQueries = append(fileQueries, caching.GitHubFileQuery{
						RepoOwner: *checkSuitePayload.Repo.Owner.Login,
						RepoName:  *checkSuitePayload.Repo.Name,
						CommitSHA: *commitSha,
						FileName:  *file.Filename,
						Status:    fileStatus,
					})
				}
			}

			commitScanResults, err := handler.Scanner.CheckFileContentFromQueries(
				handler.GitHubClient,
				fileQueries)
			if err != nil {
				handler.handleFailure(
					checkRun,
					fmt.Sprintf("Failed to scan commits from pull request #%d", pullRequest.Number),
					err)
				return
			}

			if len(commitScanResults) > 0 {

				// Todo: Once scan results are persisted, only act on new scan results

				// If all matches are resolved, pass the check, but reply with a reminder that the matches can still be
				//	viewed in the commit history
				var conclusion checkRunConclusion
				if AllMatchesAreResolved(commitScanResults) {
					log.Info().Msgf("Matches found but resolved in pull request #%d, passing check with reminder", pullRequest.Number)
					conclusion = checkRunConclusionSuccess

					// Reply with reminder
					body := "## :warning: Heads up!\n"
					body += "It looks like there is _potentially_ sensitive information in the commit history, but it appears to have since been removed.\n"
					body += fmt.Sprintf("See the [Orca check results](%s) for more information.\n", *checkRun.HTMLURL)
					body += "If any sensitive information is in the history, please make sure it is addressed appropriately." // Todo: Reword this line
					_, _, err := handler.GitHubClient.Issues.CreateComment(
						context.Background(),
						*checkSuitePayload.Repo.Owner.Login,
						*checkSuitePayload.Repo.Name,
						*pullRequest.Number,
						&github.IssueComment{
							Body: &body,
						})
					if err != nil {
						handler.handleFailure(checkRun, "Failed to reply to Pull Request with commit history warning", err)
						return
					}
				} else {
					log.Debug().Msg("Potentially sensitive information detected, failing check")
					conclusion = checkRunConclusionFailure
				}

				title, text := BuildMessage(commitScanResults)
				handler.completeCheckRun(checkRun, conclusion, title, &text)

				return
			} else {
				log.Debug().Msg("No matches to address")
			}
		}

		// Made it here, all is well
		handler.completeCheckRun(checkRun, checkRunConclusionSuccess, "No issues detected", nil)
	} else {
		handler.completeCheckRun(
			checkRun,
			checkRunConclusionSkipped,
			"No Pull Requests found. Orca Checks are currently only supported from Pull Requests",
			nil)
		log.Info().Msg("No pull request exists, skipping")
	}
}

func (handler *PayloadHandler) handleFailure(checkRun *github.CheckRun, summary string, err error) {
	handler.updateCheckRun(
		checkRun,
		checkRunStatusCompleted,
		checkRunConclusionFailure,
		summary,
		nil)
	log.Error().Msgf("Check run %d failed: %v", checkRun.ID, err)
}

func (handler *PayloadHandler) completeCheckRun(checkRun *github.CheckRun, conclusion checkRunConclusion, summary string, text *string) {
	handler.updateCheckRun(
		checkRun,
		checkRunStatusCompleted,
		conclusion,
		summary,
		text)
	log.Debug().Msgf("Check run %d completed with conclusion \"%s\"", checkRun.ID, conclusion)
}

func (handler *PayloadHandler) updateCheckRun(
	checkRun *github.CheckRun,
	status checkRunStatus,
	conclusion checkRunConclusion,
	summary string,
	text *string) {

	statusString := string(status)
	conclusionString := string(conclusion)
	outputTitle := "Orca Checks"

	_, _, err := handler.GitHubClient.Checks.UpdateCheckRun(
		context.Background(),
		*checkRun.CheckSuite.Repository.Owner.Login,
		*checkRun.CheckSuite.Repository.Name,
		*checkRun.ID,
		github.UpdateCheckRunOptions{
			Status:     &statusString,
			Conclusion: &conclusionString,
			Output: &github.CheckRunOutput{
				Title:   &outputTitle,
				Summary: &summary,
				Text:    text,
			},
		})

	if err != nil {
		// TODO: At this point we're going to have an abandoned check,
		// 	need to persist these checks somewhere so we can clean them up after a failure
		log.Error().Msgf("Failed to update check run %d: %v", checkRun.ID, err)
	}
}

func AllMatchesAreResolved(scanResults []scanning.CommitScanResult) bool {
	for _, result := range scanResults {
		for _, match := range result.Matches {
			if !match.Resolved {
				return false
			}
		}
	}

	return true
}
