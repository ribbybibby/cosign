//
// Copyright 2021 The Sigstore Authors.
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

package download

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign"
)

func SBOMCmd(ctx context.Context, opts options.DownloadSBOMOptions, imageRef string, out io.Writer) ([]string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	ociremoteOpts, err := opts.Registry.ClientOpts(ctx)
	if err != nil {
		return nil, err
	}

	var sbom *cosign.AttachmentPayload

	if opts.Platform != "" {
		platform, err := v1.ParsePlatform(opts.Platform)
		if err != nil {
			return nil, err
		}

		sbom, err = cosign.FetchAttachmentFromIndex(ctx, ref, *platform, cosign.SBOM, ociremoteOpts...)
		if err != nil {
			return nil, err
		}
	} else {
		sbom, err = cosign.FetchAttachmentForReference(ctx, ref, cosign.SBOM, ociremoteOpts...)
		if err != nil {
			return nil, err
		}
	}

	// "attach sbom" attaches a single static.NewFile
	sboms := make([]string, 0, 1)

	fmt.Fprintf(os.Stderr, "Found SBOM of media type: %s\n", sbom.FileMediaType)

	sboms = append(sboms, string(sbom.Payload))
	fmt.Fprintln(out, string(sbom.Payload))

	return sboms, nil
}
