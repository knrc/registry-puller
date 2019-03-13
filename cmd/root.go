// Copyright © 2019 Kevin Conner <kev.conner@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/knrc/registry-puller/pkg/webhook"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "registry-puller",
	Short: "A webhook for automatically attaching a pull secret to service accounts",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.AddCommand(webhookCmd())
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.registry-puller.yaml)")
}

func webhookCmd() *cobra.Command {
	var (
		webhookArgs = webhook.DefaultArgs()
	)

	webhookCmd := &cobra.Command{
		Use:          "webhook",
		Short:        "Starts a server for handling the webhook",
		SilenceUsage: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := webhookArgs.Validate(); err != nil {
				log.Panicf("Invalid webhook args: %v", err)
			}

			// Create the stop channel for all of the servers.
			stop := make(chan struct{})

			go webhook.RunWebhook(webhookArgs, stop)

			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
			<-sigs
			close(stop)
		},
	}
	webhookCmd.PersistentFlags().StringVar(&webhookArgs.CertFile, "tlsCertFile", "/etc/certs/cert-chain.pem",
		"File containing the x509 Certificate for HTTPS.")
	webhookCmd.PersistentFlags().StringVar(&webhookArgs.KeyFile, "tlsKeyFile", "/etc/certs/key.pem",
		"File containing the x509 private key matching --tlsCertFile.")
	webhookCmd.PersistentFlags().StringVar(&webhookArgs.CACertFile, "caCertFile", "/etc/certs/root-cert.pem",
		"File containing the caBundle that signed the cert/key specified by --tlsCertFile and --tlsKeyFile.")

	webhookCmd.PersistentFlags().StringVar(&webhookArgs.WebhookConfigFile,
		"webhook-config-file", "",
		"File that contains k8s mutatingwebhookconfiguration yaml.")
	webhookCmd.PersistentFlags().UintVar(&webhookArgs.Port, "port", 443,
		"HTTPS port of the webhook service.")
	webhookCmd.PersistentFlags().StringVar(&webhookArgs.Namespace, "namespace", "registry-puller",
		"Namespace of the deployment for the pod")
	webhookCmd.PersistentFlags().StringVar(&webhookArgs.DeploymentName, "deployment-name", "registry-puller",
		"Name of the deployment for the pod")
	webhookCmd.PersistentFlags().StringVar(&webhookArgs.RegistrySecretFile,
		"registry-secret-file", "",
		"Name of the yaml file containing the registry secret")

	webhookCmd.PersistentFlags().StringVar(&webhookArgs.WebhookName, "webhook-name", "registry-puller",
		"Name of the MutatingWebhookConfiguration resource in Kubernetes")

	return webhookCmd
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".registry-puller" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".registry-puller")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
