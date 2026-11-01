// Command kubectl-capybara is the kubecapybara CLI and terminal dashboard.
// Installed on the PATH it works as a kubectl plugin: `kubectl capybara`.
package main

import "github.com/galq5/kubecapybara/internal/cli"

var version = "dev"

func main() { cli.Execute(version) }
