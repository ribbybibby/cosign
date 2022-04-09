//
// Copyright 2022 The Sigstore Authors.
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

package options

import (
	"github.com/spf13/cobra"
)

// DownloadSBOMOptions is the top level wrapper for the download sbom command
type DownloadSBOMOptions struct {
	Platform string
	Registry RegistryOptions
}

var _ Interface = (*DownloadSBOMOptions)(nil)

// AddFlags implements Interface
func (o *DownloadSBOMOptions) AddFlags(cmd *cobra.Command) {
	o.Registry.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Platform, "platform", "",
		"download from a specific platform in a multi-arch image. The format is os/arch[/variant][:osversion]")
}
