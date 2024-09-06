// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

package packager2

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseunicorns/pkg/helpers/v2"
	"github.com/defenseunicorns/pkg/oci"
	"github.com/mholt/archiver/v3"

	"github.com/zarf-dev/zarf/src/config"
	"github.com/zarf-dev/zarf/src/pkg/layout"
	"github.com/zarf-dev/zarf/src/pkg/packager/filters"
	"github.com/zarf-dev/zarf/src/pkg/packager/sources"
	"github.com/zarf-dev/zarf/src/pkg/utils"
	"github.com/zarf-dev/zarf/src/pkg/zoci"
	"github.com/zarf-dev/zarf/src/types"
)

// LoadPackageFromSource optionally fetches and loads the package from the given source.
func LoadPackageFromSource(ctx context.Context, src, shasum, publicKeyPath string, filter filters.ComponentFilterStrategy) (*layout.PackagePaths, error) {
	srcType, err := identifySource(src)
	if err != nil {
		return nil, err
	}

	packageDir, err := utils.MakeTempDir(config.CommonOptions.TempDirectory)
	if err != nil {
		return nil, err
	}

	// OCI loads differently as it can fetch partial packages.
	if srcType == "oci" {
		pkgPaths, err := fetchOCI(ctx, src, shasum, publicKeyPath, packageDir, filter)
		if err != nil {
			return nil, err
		}
		return pkgPaths, nil
	}

	tarDir, err := utils.MakeTempDir(config.CommonOptions.TempDirectory)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tarDir)
	tarPath := filepath.Join(tarDir, "packager.tar")

	switch srcType {
	case "tarball":
		tarPath = src
	case "sget":
		return nil, fmt.Errorf("deprecated")
	case "http", "https":
		err := fetchHTTP(ctx, src, tarPath)
		if err != nil {
			return nil, err
		}
	case "split":
		err := assembleSplitTar(src, tarPath)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown source type: %s", src)
	}

	if shasum != "" {
		err := helpers.SHAsMatch(tarPath, shasum)
		if err != nil {
			return nil, err
		}
	}
	pathsExtracted := []string{}
	err = archiver.Walk(src, func(f archiver.File) error {
		if f.IsDir() {
			return nil
		}
		header, ok := f.Header.(*tar.Header)
		if !ok {
			return fmt.Errorf("expected header to be *tar.Header but was %T", f.Header)
		}
		// If path has nested directories we want to create them.
		dir := filepath.Dir(header.Name)
		if dir != "." {
			err := os.MkdirAll(filepath.Join(packageDir, dir), helpers.ReadExecuteAllWriteUser)
			if err != nil {
				return err
			}
		}
		dst, err := os.Create(filepath.Join(packageDir, header.Name))
		if err != nil {
			return err
		}
		defer dst.Close()
		_, err = io.Copy(dst, f)
		if err != nil {
			return err
		}
		pathsExtracted = append(pathsExtracted, header.Name)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Load the package paths
	pkgPaths := layout.New(packageDir)
	pkgPaths.SetFromPaths(pathsExtracted)
	pkg, _, err := pkgPaths.ReadZarfYAML()
	if err != nil {
		return nil, err
	}
	pkg.Components, err = filter.Apply(pkg)
	if err != nil {
		return nil, err
	}
	if err := pkgPaths.MigrateLegacy(); err != nil {
		return nil, err
	}
	if !pkgPaths.IsLegacyLayout() {
		if err := sources.ValidatePackageIntegrity(pkgPaths, pkg.Metadata.AggregateChecksum, false); err != nil {
			return nil, err
		}
		if err := sources.ValidatePackageSignature(ctx, pkgPaths, publicKeyPath); err != nil {
			return nil, err
		}
	}
	for _, component := range pkg.Components {
		if err := pkgPaths.Components.Unarchive(component); err != nil {
			if errors.Is(err, layout.ErrNotLoaded) {
				_, err := pkgPaths.Components.Create(component)
				if err != nil {
					return nil, err
				}
			} else {
				return nil, err
			}
		}
	}
	if pkgPaths.SBOMs.Path != "" {
		if err := pkgPaths.SBOMs.Unarchive(); err != nil {
			return nil, err
		}
	}
	return pkgPaths, nil
}

func identifySource(src string) (string, error) {
	parsed, err := url.Parse(src)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return parsed.Scheme, nil
	}
	if strings.HasSuffix(src, ".tar.zst") || strings.HasSuffix(src, ".tar") {
		return "tarball", nil
	}
	if strings.Contains(src, ".part000") {
		return "split", nil
	}
	return "", fmt.Errorf("unknown source %s", src)
}

func assembleSplitTar(src, tarPath string) error {
	pattern := strings.Replace(src, ".part000", ".part*", 1)
	splitFiles, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("unable to find split tarball files: %w", err)
	}
	// Ensure the files are in order so they are appended in the correct order
	sort.Strings(splitFiles)

	tarFile, err := os.Create(tarPath)
	if err != nil {
		return err
	}
	defer tarFile.Close()

	var pkgData types.ZarfSplitPackageData
	for _, splitFile := range splitFiles {
		f, err := os.Open(splitFile)
		if err != nil {
			return fmt.Errorf("unable to open file %s: %w", splitFile, err)
		}
		defer f.Close()
		_, err = io.Copy(tarFile, f)
		if err != nil {
			return fmt.Errorf("unable to copy file %s: %w", splitFile, err)
		}
		err = f.Close()
		if err != nil {
			return fmt.Errorf("unable to close file %s: %w", splitFile, err)
		}
	}
	if err := helpers.SHAsMatch(tarPath, pkgData.Sha256Sum); err != nil {
		return fmt.Errorf("package integrity check failed: %w", err)
	}
	return nil
}

func fetchHTTP(ctx context.Context, src, tarPath string) error {
	src, checksum, err := parseChecksum(src)
	if err != nil {
		return err
	}
	f, err := os.Create(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, err := io.Copy(io.Discard, resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected http response status code %s for source %s", resp.Status, src)
	}
	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return err
	}
	// Check checksum if src inccluded one.
	if checksum != "" {
		received, err := helpers.GetSHA256OfFile(tarPath)
		if err != nil {
			return err
		}
		if received != checksum {
			return fmt.Errorf("shasum mismatch for file %s, expected %s bu got %s ", tarPath, checksum, received)
		}
	}
	return nil
}

func parseChecksum(src string) (string, string, error) {
	atSymbolCount := strings.Count(src, "@")
	var checksum string
	if atSymbolCount > 0 {
		parsed, err := url.Parse(src)
		if err != nil {
			return src, checksum, fmt.Errorf("unable to parse the URL: %s", src)
		}
		if atSymbolCount == 1 && parsed.User != nil {
			return src, checksum, nil
		}

		index := strings.LastIndex(src, "@")
		checksum = src[index+1:]
		src = src[:index]
	}
	return src, checksum, nil
}

func fetchOCI(ctx context.Context, src, shasum, publicKeyPath, packageDir string, filter filters.ComponentFilterStrategy) (*layout.PackagePaths, error) {
	if shasum != "" {
		src = fmt.Sprintf("%s@sha256:%s", src, shasum)
	}
	arch := config.GetArch()
	remote, err := zoci.NewRemote(src, oci.PlatformForArch(arch))
	if err != nil {
		return nil, err
	}

	pkg, err := remote.FetchZarfYAML(ctx)
	if err != nil {
		return nil, err
	}
	pkg.Components, err = filter.Apply(pkg)
	if err != nil {
		return nil, err
	}

	layersToPull, err := remote.LayersFromRequestedComponents(ctx, pkg.Components)
	if err != nil {
		return nil, fmt.Errorf("unable to get published component image layers: %s", err.Error())
	}

	isPartial := true
	root, err := remote.FetchRoot(ctx)
	if err != nil {
		return nil, err
	}
	if len(root.Layers) == len(layersToPull) {
		isPartial = false
	}

	layersFetched, err := remote.PullPackage(ctx, packageDir, config.CommonOptions.OCIConcurrency, layersToPull...)
	if err != nil {
		return nil, fmt.Errorf("unable to pull the package: %w", err)
	}

	pkgPaths := layout.New(packageDir)
	pkgPaths.SetFromLayers(layersFetched)

	if err := pkgPaths.MigrateLegacy(); err != nil {
		return nil, err
	}

	if !pkgPaths.IsLegacyLayout() {
		if err := sources.ValidatePackageIntegrity(pkgPaths, pkg.Metadata.AggregateChecksum, isPartial); err != nil {
			return nil, err
		}
		if err := sources.ValidatePackageSignature(ctx, pkgPaths, publicKeyPath); err != nil {
			return nil, err
		}
	}

	for _, component := range pkg.Components {
		if err := pkgPaths.Components.Unarchive(component); err != nil {
			if errors.Is(err, layout.ErrNotLoaded) {
				_, err := pkgPaths.Components.Create(component)
				if err != nil {
					return nil, err
				}
			} else {
				return nil, err
			}
		}
	}

	if pkgPaths.SBOMs.Path != "" {
		if err := pkgPaths.SBOMs.Unarchive(); err != nil {
			return nil, err
		}
	}
	return pkgPaths, nil
}
