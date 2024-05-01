// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package hooks contains the mutation hooks for the Zarf agent.
package hooks

import (
	"encoding/json"
	"fmt"

	"github.com/defenseunicorns/pkg/helpers"
	"github.com/defenseunicorns/zarf/src/config"
	"github.com/defenseunicorns/zarf/src/config/lang"
	"github.com/defenseunicorns/zarf/src/internal/agent/operations"
	"github.com/defenseunicorns/zarf/src/internal/agent/state"
	"github.com/defenseunicorns/zarf/src/pkg/message"
	"github.com/defenseunicorns/zarf/src/pkg/transform"
	"github.com/defenseunicorns/zarf/src/types"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Ref contains the tag used to reference am image.
type Ref struct {
	Tag    string `json:"tag,omitempty"`
	Digest string `json:"digest,omitempty"`
	Semver string `json:"semver,omitempty"`
}

// OCIRepo contains the URL of a git repo and the secret that corresponds to it for use with Flux.
type OCIRepo struct {
	Spec struct {
		URL       string    `json:"url"`
		SecretRef SecretRef `json:"secretRef,omitempty"`
		Ref       Ref       `json:"ref,omitempty"`
	} `json:"spec"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
}

// NewOCIRepositoryMutationHook creates a new instance of the oci repo mutation hook.
func NewOCIRepositoryMutationHook() operations.Hook {
	message.Debug("hooks.NewOCIRepositoryMutationHook()")
	return operations.Hook{
		Create: mutateOCIRepo,
		Update: mutateOCIRepo,
	}
}

// mutateOCIRepo mutates the oci repository url to point to the repository URL defined in the ZarfState.
func mutateOCIRepo(r *v1.AdmissionRequest) (result *operations.Result, err error) {
	var (
		zarfState *types.ZarfState
		patches   []operations.PatchOperation
	)

	// Parse into a simple struct to read the OCIRepo url
	src := &OCIRepo{}
	if err = json.Unmarshal(r.Object.Raw, &src); err != nil {
		return nil, fmt.Errorf(lang.ErrUnmarshal, err)
	}

	// If we have a semver we want to continue since we wil still have the upstream tag
	// but should warn that we can't guarantee there won't be collisions
	if src.Spec.Ref.Semver != "" {
		message.Warnf(lang.AgentWarnSemVerRef, src.Spec.Ref.Semver)
	}

	if src.Labels != nil && src.Labels["zarf-agent"] == "patched" {
		message.Debugf("helmrepo in this object woohoo %v", src.ObjectMeta)
		return &operations.Result{
			Allowed:  true,
			PatchOps: patches,
		}, nil
	}

	// Form the zarfState.RegistryServer.Address from the zarfState
	if zarfState, err = state.GetZarfStateFromAgentPod(); err != nil {
		return nil, fmt.Errorf(lang.AgentErrGetState, err)
	}

	// Get the registry service info if this is a NodePort service to use the internal kube-dns
	registryAddress, err := state.GetServiceInfoFromRegistryAddress(zarfState.RegistryInfo.Address)
	if err != nil {
		return nil, err
	}

	// For the internal registry this will be the ip & port of the service, it may look like 10.43.36.151:5000
	message.Debugf("Using the url of (%s) to mutate the flux OCIRepository", registryAddress)

	// Mutate the OCIRepo URL if necessary
	ref := src.Spec.URL
	if src.Spec.Ref.Digest != "" {
		ref = fmt.Sprintf("%s@%s", ref, src.Spec.Ref.Digest)
	} else {
		ref = fmt.Sprintf("%s:%s", ref, src.Spec.Ref.Tag)
	}

	patchedSrc, err := transform.ImageTransformHost(registryAddress, ref)
	if err != nil {
		message.Warnf("Unable to transform the OCIRepo URL, using the original url we have: %s", src.Spec.URL)
		return &operations.Result{Allowed: true}, nil
	}

	patchedRefInfo, err := transform.ParseImageRef(patchedSrc)
	if err != nil {
		message.Warnf("Unable to parse the transformed OCIRepo URL, using the original url we have: %s", src.Spec.URL)
		return &operations.Result{Allowed: true}, nil
	}
	patchedRef := src.Spec.Ref

	patchedURL := helpers.OCIURLPrefix + patchedRefInfo.Name

	if patchedRefInfo.Digest != "" {
		patchedRef.Digest = patchedRefInfo.Digest
	} else {
		patchedRef.Tag = patchedRefInfo.Tag
	}

	message.Debugf("original OCIRepo URL of (%s) got mutated to (%s)", src.Spec.URL, patchedURL)

	patches = populateOCIRepoPatchOperations(patchedURL, zarfState.RegistryInfo.InternalRegistry, patchedRef)
	return &operations.Result{
		Allowed:  true,
		PatchOps: patches,
	}, nil
}

// Patch updates of the repo spec.
func populateOCIRepoPatchOperations(repoURL string, isInternal bool, ref Ref) []operations.PatchOperation {
	var patches []operations.PatchOperation
	patches = append(patches, operations.ReplacePatchOperation("/spec/url", repoURL))

	patches = append(patches, operations.AddPatchOperation("/spec/secretRef", SecretRef{Name: config.ZarfImagePullSecretName}))

	if isInternal {
		patches = append(patches, operations.ReplacePatchOperation("/spec/insecure", true))
	}

	patches = append(patches, operations.ReplacePatchOperation("/metadata/labels/zarf-agent", "patched"))

	if ref.Tag != "" {
		patches = append(patches, operations.ReplacePatchOperation("/spec/ref/tag", ref.Tag))
	} else if ref.Digest != "" {
		patches = append(patches, operations.ReplacePatchOperation("/spec/ref/digest", ref.Digest))
	} else {
		patches = append(patches, operations.AddPatchOperation("/spec/ref", ref))
	}

	return patches
}
