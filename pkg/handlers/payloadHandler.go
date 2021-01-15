package handlers

import (
	"Orca/pkg/api"
	"Orca/pkg/scanning"
	"context"
	"crypto/rsa"
	"fmt"
	"github.com/google/go-github/v33/github"
	"github.com/rs/zerolog/log"
)

type PayloadHandler struct {
	InstallationId int64
	AppId          int
	GitHubClient   *github.Client
	Scanner        *scanning.Scanner
}

func NewPayloadHandler(
	installationId int64,
	appId int,
	privateKey *rsa.PrivateKey,
	patternStore *scanning.PatternStore) (*PayloadHandler, error) {

	scanner, err := scanning.NewScanner(patternStore)
	if err != nil {
		return nil, err
	}

	gitHubApiClient, err := api.GetGitHubApiClient(installationId, appId, privateKey)
	if err != nil {
		return nil, err
	}

	handler := PayloadHandler{
		InstallationId: installationId,
		AppId:          appId,
		GitHubClient:   gitHubApiClient,
		Scanner:        scanner,
	}

	return &handler, nil
}

func (handler *PayloadHandler) HandleInstallation(installationPayload *github.InstallationEvent) {
	log.Info().Msgf("Handling installation event from %s", *installationPayload.Sender.Login)

	// Todo: Scan the repository for any sensitive information
	// 	May not be viable for large repositories with a long history
}

func (handler *PayloadHandler) HandlePush(pushPayload *github.PushEvent) {
	log.Info().Msgf(
		"Handling push event from %s/%s to ref %s",
		*pushPayload.Repo.Owner.Login,
		*pushPayload.Repo.Name,
		*pushPayload.Ref)

	// If any Pull Requests are open for ths branch, then ignore this and let the CI check handle it
	pullRequests, _, err := handler.GitHubClient.PullRequests.List(
		context.Background(),
		*pushPayload.Repo.Owner.Login,
		*pushPayload.Repo.Name,
		&github.PullRequestListOptions{
			State:       "open",
			Head:        fmt.Sprintf("%s:%s", *pushPayload.Pusher.Name, *pushPayload.Ref),
		})

	// If a pull request exists, then the CI check will do the work for us here, no need to continue
	if len(pullRequests) > 0 {
		log.Info().Msgf("Pull request already exists for %s, skipping check", *pushPayload.Ref)
		return
	}

	// Check the commits
	commitScanResults, err := handler.Scanner.CheckPush(pushPayload, handler.GitHubClient)
	if err != nil {
		log.Error().Err(err)
		return
	}

	// If anything shows up in the results, take action
	if len(commitScanResults) > 0 {
		log.Debug().Msg("Potentially sensitive information detected")
		matchHandler := NewMatchHandler(handler.GitHubClient)
		err := matchHandler.HandleMatchesFromPush(pushPayload, commitScanResults)
		if err != nil {
			log.Error().Err(err)
			return
		}

		log.Debug().Msg("Matches addressed")
	} else {
		log.Debug().Msg("No matches to address")
	}
}

func (handler *PayloadHandler) HandleIssue(issuePayload *github.IssuesEvent) {
	log.Info().Msgf(
		"Handling issue event from %s/%s#%d",
		*issuePayload.Repo.Owner.Login,
		*issuePayload.Repo.Name,
		*issuePayload.Issue.Number)

	// Check the contents of the issue
	issueScanResult, err := handler.Scanner.CheckIssue(issuePayload)
	if err != nil {
		log.Error().Err(err)
		return
	}

	// If anything shows up in the results, take action
	if issueScanResult.HasMatches() {
		log.Debug().Msg("Potentially sensitive information detected")
		matchHandler := NewMatchHandler(handler.GitHubClient)
		err := matchHandler.HandleMatchesFromIssue(issuePayload, issueScanResult)
		if err != nil {
			log.Error().Err(err)
			return
		}

		log.Debug().Msg("Matches addressed")
	} else {
		log.Debug().Msg("No matches to address")
	}
}

func (handler *PayloadHandler) HandleIssueComment(issueCommentPayload *github.IssueCommentEvent) {
	log.Info().Msgf(
		"Handling issue comment event from %s/%s#%d (%d)",
		*issueCommentPayload.Repo.Owner.Login,
		*issueCommentPayload.Repo.Name,
		*issueCommentPayload.Issue.Number,
		*issueCommentPayload.Comment.ID)

	// Check the contents of the comment
	issueScanResult, err := handler.Scanner.CheckIssueComment(issueCommentPayload)
	if err != nil {
		log.Error().Err(err)
		return
	}

	// If anything shows up in the results, take action
	if issueScanResult.HasMatches() {
		log.Debug().Msg("Potentially sensitive information detected")
		matchHandler := NewMatchHandler(handler.GitHubClient)
		err := matchHandler.HandleMatchesFromIssueComment(issueCommentPayload, issueScanResult)
		if err != nil {
			log.Error().Err(err)
			return
		}

		log.Debug().Msg("Matches addressed")
	} else {
		log.Debug().Msg("No matches to address")
	}
}

func (handler *PayloadHandler) HandlePullRequest(pullRequestPayload *github.PullRequestEvent) {
	log.Info().Msgf(
		"Handling pull request event from %s/%s#%d",
		*pullRequestPayload.Repo.Owner.Login,
		*pullRequestPayload.Repo.Name,
		*pullRequestPayload.PullRequest.Number)

	// Check the contents of the pull request
	pullRequestScanResult, err := handler.Scanner.CheckPullRequest(pullRequestPayload)
	if err != nil {
		log.Error().Err(err)
		return
	}

	// If anything shows up in the results, take action
	if pullRequestScanResult.HasMatches() {
		log.Debug().Msg("Potentially sensitive information detected")
		matchHandler := NewMatchHandler(handler.GitHubClient)
		err := matchHandler.HandleMatchesFromPullRequest(pullRequestPayload, pullRequestScanResult)
		if err != nil {
			log.Error().Err(err)
			return
		}

		log.Debug().Msg("Matches addressed")
	} else {
		log.Debug().Msg("No matches to address")
	}
}

func (handler *PayloadHandler) HandlePullRequestReview(pullRequestReviewPayload *github.PullRequestReviewEvent) {
	log.Info().Msgf(
		"Handling pull request review event from %s/%s#%d (%d)",
		*pullRequestReviewPayload.Repo.Owner.Login,
		*pullRequestReviewPayload.Repo.Name,
		*pullRequestReviewPayload.PullRequest.Number,
		*pullRequestReviewPayload.Review.ID)

	// Check the contents of the pull request review
	pullRequestReviewScanResult, err := handler.Scanner.CheckPullRequestReview(pullRequestReviewPayload)
	if err != nil {
		log.Error().Err(err)
		return
	}

	// If anything shows up in the results, take action
	if pullRequestReviewScanResult.HasMatches() {
		log.Debug().Msg("Potentially sensitive information detected")
		matchHandler := NewMatchHandler(handler.GitHubClient)
		err := matchHandler.HandleMatchesFromPullRequestReview(pullRequestReviewPayload, pullRequestReviewScanResult)
		if err != nil {
			log.Error().Err(err)
			return
		}

		log.Debug().Msg("Matches addressed")
	} else {
		log.Debug().Msg("No matches to address")
	}
}

func (handler *PayloadHandler) HandlePullRequestReviewComment(
	pullRequestReviewCommentPayload *github.PullRequestReviewCommentEvent) {
	log.Info().Msgf(
		"Handling pull request review comment event from %s/%s#%d (%d)",
		*pullRequestReviewCommentPayload.Repo.Owner.Login,
		*pullRequestReviewCommentPayload.Repo.Name,
		*pullRequestReviewCommentPayload.PullRequest.Number,
		*pullRequestReviewCommentPayload.Comment.ID)

	// Check the contents of the pull request review
	pullRequestReviewCommentScanResult, err := handler.Scanner.CheckPullRequestReviewComment(pullRequestReviewCommentPayload)
	if err != nil {
		log.Error().Err(err)
		return
	}

	// If anything shows up in the results, take action
	if pullRequestReviewCommentScanResult.HasMatches() {
		log.Debug().Msg("Potentially sensitive information detected")
		matchHandler := NewMatchHandler(handler.GitHubClient)
		err := matchHandler.HandleMatchesFromPullRequestReviewComment(
			pullRequestReviewCommentPayload,
			pullRequestReviewCommentScanResult)
		if err != nil {
			log.Error().Err(err)
			return
		}

		log.Debug().Msg("Matches addressed")
	} else {
		log.Debug().Msg("No matches to address")
	}
}
