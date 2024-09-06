// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

package dns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsServiceURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		serviceURL string
		expected   bool
	}{
		{
			name:       "is service url",
			serviceURL: "http://registry.zarf.svc.cluster.local:1",
			expected:   true,
		},
		{
			name:       "is not service url",
			serviceURL: "https://zarf.dev",
			expected:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := IsServiceURL(tt.serviceURL)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestParseServiceURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		serviceURL        string
		expectedErr       string
		expectedNamespace string
		expectedName      string
		expectedPort      int
	}{
		{
			name:              "correct service url",
			serviceURL:        "http://foo.bar.svc.cluster.local:5000",
			expectedNamespace: "bar",
			expectedName:      "foo",
			expectedPort:      5000,
		},
		{
			name:        "invalid service url without port",
			serviceURL:  "http://google.com",
			expectedErr: "service url does not have a port",
		},
		{
			name:        "invalid service url with port",
			serviceURL:  "http://google.com:3000",
			expectedErr: "invalid service url http://google.com:3000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			namespace, name, port, err := ParseServiceURL(tt.serviceURL)
			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
				return
			}
			require.Equal(t, tt.expectedNamespace, namespace)
			require.Equal(t, tt.expectedName, name)
			require.Equal(t, tt.expectedPort, port)
		})
	}
}
