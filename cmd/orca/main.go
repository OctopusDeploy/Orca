package main

import (
	"Orca/pkg/crypto"
	"Orca/pkg/handlers"
	"Orca/pkg/scanning"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/urfave/cli/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"net/http"
	"os"
	"strings"
)

func main() {

	var path string
	var port int
	var privateKeyFile string
	var privateKeyString string
	var secret string
	var appId int
	var patternsLocation string
	var showDebugLogs bool

	app := &cli.App{
		Name:  "Orca",
		Usage: "A GitHub App that hunts for potential credentials in GitHub repositories, issues and pull requests.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "path",
				Aliases:     []string{"ph"},
				Value:       "/webhooks",
				EnvVars:     []string{"ORCA_PATH"},
				Usage:       "Path to listen for WebHook requests", // Todo: Fix wording
				Destination: &path,
			},
			&cli.IntFlag{
				Name:        "port",
				Aliases:     []string{"pt"},
				Value:       80,
				EnvVars:     []string{"ORCA_PORT"},
				Usage:       "Port to listen on", // Todo: Fix wording
				Destination: &port,
			},
			&cli.StringFlag{
				Name:        "private-key-file",
				Aliases:     []string{"pkf"},
				Usage:       "GitHub private key file for the Orca app. Expects that the private key in PEM format.",
				Destination: &privateKeyFile,
			},
			&cli.StringFlag{
				Name:        "private-key",
				Aliases:     []string{"pk"},
				EnvVars:     []string{"GITHUB_ORCA_PRIVATE_KEY"},
				Usage:       "GitHub private key for the Orca app. Expects that the private key in PEM format.",
				Destination: &privateKeyString,
			},
			&cli.StringFlag{
				Name:        "secret",
				Aliases:     []string{"s"},
				EnvVars:     []string{"GITHUB_ORCA_WEBHOOK_SECRET"},
				Usage:       "The secret is used to verify that webhooks are sent by GitHub.",
				Destination: &secret,
			},
			&cli.IntFlag{
				Name:        "app-id",
				Aliases:     []string{"id"},
				EnvVars:     []string{"GITHUB_ORCA_APP_ID"},
				Usage:       "The GitHub App's identifier (type integer) set when registering an app.",
				Destination: &appId,
			},
			&cli.StringFlag{
				Name:        "patterns-location",
				Aliases:     []string{"pl"},
				EnvVars:     []string{"ORCA_PATTERNS_LOCATION"},
				Usage:       "The location of the patterns to check for. Accepts a file path or HTTP URL.",
				Destination: &patternsLocation,
			},
			&cli.BoolFlag{
				Name:        "show-debug-logs",
				Aliases:     []string{"d"},
				Usage:       "Show debug logs.",
				Destination: &showDebugLogs,
			},
		},
		Action: func(c *cli.Context) error {

			// Check the webhook path
			if len(path) < 1 {
				return errors.New("a webhook path must be provided")
			}

			// Check the port number is valid
			if port > 65535 || port < 1 {
				return errors.New("a valid port number must be provided")
			}

			// Check and decode the private key
			var privateKey *rsa.PrivateKey
			var err error
			if len(privateKeyFile) > 0 {
				privateKey, err = crypto.DecodePrivateKeyFromFile(privateKeyFile)
			} else if len(privateKeyString) > 0 {
				// Replace escaped newlines with actual new lines
				// Todo: I wonder if this is a bad idea? GitHubs own ruby template does this so it should be fine
				var privateKeyWithNewLines = strings.ReplaceAll(privateKeyString, "\\n", "\n")
				var privateKeyBytes = []byte(privateKeyWithNewLines)
				privateKey, err = crypto.DecodePrivateKey(privateKeyBytes)
			} else {
				return errors.New("a private key must be provided")
			}

			if err != nil {
				return err
			}

			// Check the secret
			if len(secret) < 1 {
				return errors.New("a secret must be provided")
			}

			// Check the app ID
			if appId < 1 {
				return errors.New("an app id must be provided")
			}

			// Get the Pattern store
			patternStore, err := scanning.NewPatternStore(patternsLocation)
			if err != nil {
				return err
			}

			zerolog.SetGlobalLevel(zerolog.InfoLevel)
			log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
			if showDebugLogs {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}

			// Setup webhook handlers
			webHookHandler := handlers.NewWebhookHandler(path, appId, &patternStore, privateKey, secret)

			// Start HTTP webhooks
			log.Info().Msgf("Starting webhooks at port %d", port)
			var address = fmt.Sprintf(":%d", port)
			if err := http.ListenAndServe(address, webHookHandler); err != nil {
				return err
			}

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err)
	}
}
