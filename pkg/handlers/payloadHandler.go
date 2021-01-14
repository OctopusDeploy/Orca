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

	// Todo: Scan the repository for any sensitive information
	// 	May not be viable for large repositories with a long history
}

func (handler *PayloadHandler) HandlePush(pushPayload *github.PushEvent) {
	log.Info().Msg("Handling push...")

	// If any Pull Requests are open for ths branch, then ignore this and let the CI check handle it
	pullRequests, _, err := handler.GitHubClient.PullRequests.List(
		context.Background(),
		*pushPayload.Repo.Owner.Login,
		*pushPayload.Repo.Name,
		&github.PullRequestListOptions{
			State:       "open",
			Head:        fmt.Sprintf("%s:%s", *pushPayload.Pusher.Name, *pushPayload.Ref),
		})

	if len(pullRequests) > 0 {
		log.Info().Msgf("Pull Request already exists for %s, skipping check on push.\n", *pushPayload.Ref)
		return
	}

	// Check the commits
	commitScanResults, err := handler.Scanner.CheckPush(pushPayload, handler.GitHubClient)
	if err != nil {
		log.Fatal().Err(err)
		return
	}

	// If anything shows up in the results, take action
	if len(commitScanResults) > 0 {
		log.Info().Msg("Potentially sensitive information detected. Rectifying...")
		matchHandler := NewMatchHandler(handler.GitHubClient)
		err := matchHandler.HandleMatchesFromPush(pushPayload, commitScanResults)
		if err != nil {
			log.Fatal().Err(err)
			return
		}

		log.Info().Msg("Push has been addressed")
	} else {
		log.Info().Msg("No matches to address")
	}
}

func (handler *PayloadHandler) HandleIssue(issuePayload *github.IssuesEvent) {
	log.Info().Msg("Handling issue...")

	// Check the contents of the issue
	issueScanResult, err := handler.Scanner.CheckIssue(issuePayload)
	if err != nil {
		log.Fatal().Err(err)
		return
	}

	// If anything shows up in the results, take action
	if issueScanResult.HasMatches() {
		log.Info().Msg("Potentially sensitive information detected. Rectifying...")
		matchHandler := NewMatchHandler(handler.GitHubClient)
		err := matchHandler.HandleMatchesFromIssue(issuePayload, issueScanResult)
		if err != nil {
			log.Fatal().Err(err)
			return
		}

		log.Info().Msg("Issue has been addressed")
	} else {
		log.Info().Msg("No matches to address")
	}
}

func (handler *PayloadHandler) HandleIssueComment(issueCommentPayload *github.IssueCommentEvent) {
	log.Info().Msg("Handling issue...")

	// Check the contents of the comment
	issueScanResult, err := handler.Scanner.CheckIssueComment(issueCommentPayload)
	if err != nil {
		log.Fatal().Err(err)
		return
	}

	// If anything shows up in the results, take action
	if issueScanResult.HasMatches() {
		log.Info().Msg("Potentially sensitive information detected. Rectifying...")
		matchHandler := NewMatchHandler(handler.GitHubClient)
		err := matchHandler.HandleMatchesFromIssueComment(issueCommentPayload, issueScanResult)
		if err != nil {
			log.Fatal().Err(err)
			return
		}

		log.Info().Msg("Issue comment has been addressed")
	} else {
		log.Info().Msg("No matches to address")
	}
}

func (handler *PayloadHandler) HandlePullRequest(pullRequestPayload *github.PullRequestEvent) {
	log.Info().Msg("Handling pull request...")

	// Check the contents of the pull request
	pullRequestScanResult, err := handler.Scanner.CheckPullRequest(pullRequestPayload)
	if err != nil {
		log.Fatal().Err(err)
		return
	}

	// If anything shows up in the results, take action
	if pullRequestScanResult.HasMatches() {
		log.Info().Msg("Potentially sensitive information detected. Rectifying...")
		matchHandler := NewMatchHandler(handler.GitHubClient)
		err := matchHandler.HandleMatchesFromPullRequest(pullRequestPayload, pullRequestScanResult)
		if err != nil {
			log.Fatal().Err(err)
			return
		}

		log.Info().Msg("Pull request has been addressed")
	} else {
		log.Info().Msg("No matches to address")
	}
}

func (handler *PayloadHandler) HandlePullRequestReview(pullRequestReviewPayload *github.PullRequestReviewEvent) {
	log.Info().Msg("Handling pull request review...")

	// Check the contents of the pull request review
	pullRequestReviewScanResult, err := handler.Scanner.CheckPullRequestReview(pullRequestReviewPayload)
	if err != nil {
		log.Fatal().Err(err)
		return
	}

	// If anything shows up in the results, take action
	if pullRequestReviewScanResult.HasMatches() {
		log.Info().Msg("Potentially sensitive information detected. Rectifying...")
		matchHandler := NewMatchHandler(handler.GitHubClient)
		err := matchHandler.HandleMatchesFromPullRequestReview(pullRequestReviewPayload, pullRequestReviewScanResult)
		if err != nil {
			log.Fatal().Err(err)
			return
		}

		log.Info().Msg("Pull request review has been addressed")
	} else {
		log.Info().Msg("No matches to address")
	}
}

func (handler *PayloadHandler) HandlePullRequestReviewComment(
	pullRequestReviewCommentPayload *github.PullRequestReviewCommentEvent) {
	log.Info().Msg("Handling pull request review comment...")

	// Check the contents of the pull request review
	pullRequestReviewCommentScanResult, err := handler.Scanner.CheckPullRequestReviewComment(pullRequestReviewCommentPayload)
	if err != nil {
		log.Fatal().Err(err)
		return
	}

	// If anything shows up in the results, take action
	if pullRequestReviewCommentScanResult.HasMatches() {
		log.Info().Msg("Potentially sensitive information detected. Rectifying...")
		matchHandler := NewMatchHandler(handler.GitHubClient)
		err := matchHandler.HandleMatchesFromPullRequestReviewComment(
			pullRequestReviewCommentPayload,
			pullRequestReviewCommentScanResult)
		if err != nil {
			log.Info().Err(err)
			return
		}

		log.Info().Msg("Pull request review comment has been addressed")
	} else {
		log.Info().Msg("No matches to address")
	}
}
