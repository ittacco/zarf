// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

package packager2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentifySource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		src             string
		expectedSrcType string
	}{
		{
			name:            "oci",
			src:             "oci://ghcr.io/defenseunicorns/packages/init:1.0.0",
			expectedSrcType: "oci",
		},
		{
			name:            "sget with sub path",
			src:             "sget://github.com/defenseunicorns/zarf-hello-world:x86",
			expectedSrcType: "sget",
		},
		{
			name:            "sget without host",
			src:             "sget://defenseunicorns/zarf-hello-world:x86_64",
			expectedSrcType: "sget",
		},
		{
			name:            "https",
			src:             "https://github.com/zarf-dev/zarf/releases/download/v1.0.0/zarf-init-amd64-v1.0.0.tar.zst",
			expectedSrcType: "https",
		},
		{
			name:            "http",
			src:             "http://github.com/zarf-dev/zarf/releases/download/v1.0.0/zarf-init-amd64-v1.0.0.tar.zst",
			expectedSrcType: "http",
		},
		{
			name:            "local tar init zst",
			src:             "zarf-init-amd64-v1.0.0.tar.zst",
			expectedSrcType: "tarball",
		},
		{
			name:            "local tar",
			src:             "zarf-package-manifests-amd64-v1.0.0.tar",
			expectedSrcType: "tarball",
		},
		{
			name:            "local tar manifest zst",
			src:             "zarf-package-manifests-amd64-v1.0.0.tar.zst",
			expectedSrcType: "tarball",
		},
		{
			name:            "local tar split",
			src:             "testdata/.part000",
			expectedSrcType: "split",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srcType, err := identifySource(tt.src)
			require.NoError(t, err)
			require.Equal(t, tt.expectedSrcType, srcType)
		})
	}
}
