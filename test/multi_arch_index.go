package test

import (
	"bytes"
	"encoding/json"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type multiArchIndex struct {
	images   map[v1.Hash]v1.Image
	manifest *v1.IndexManifest
}

// newMultiArchIndex returns an image index with a random image for each of the
// specified platforms
func newMultiArchIndex(byteSize, layers int64, platforms ...string) (v1.ImageIndex, error) {
	manifest := v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests:     []v1.Descriptor{},
	}

	images := make(map[v1.Hash]v1.Image)
	for _, p := range platforms {
		platform, err := v1.ParsePlatform(p)
		if err != nil {
			return nil, err
		}

		img, err := random.Image(byteSize, layers)
		if err != nil {
			return nil, err
		}

		rawManifest, err := img.RawManifest()
		if err != nil {
			return nil, err
		}
		digest, size, err := v1.SHA256(bytes.NewReader(rawManifest))
		if err != nil {
			return nil, err
		}
		mediaType, err := img.MediaType()
		if err != nil {
			return nil, err
		}

		manifest.Manifests = append(manifest.Manifests, v1.Descriptor{
			Digest:    digest,
			Size:      size,
			MediaType: mediaType,
			Platform:  platform,
		})

		images[digest] = img
	}

	return &multiArchIndex{
		images:   images,
		manifest: &manifest,
	}, nil
}

func (i *multiArchIndex) MediaType() (types.MediaType, error) {
	return i.manifest.MediaType, nil
}

func (i *multiArchIndex) Digest() (v1.Hash, error) {
	return partial.Digest(i)
}

func (i *multiArchIndex) Size() (int64, error) {
	return partial.Size(i)
}

func (i *multiArchIndex) IndexManifest() (*v1.IndexManifest, error) {
	return i.manifest, nil
}

func (i *multiArchIndex) RawManifest() ([]byte, error) {
	m, err := i.IndexManifest()
	if err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

func (i *multiArchIndex) Image(h v1.Hash) (v1.Image, error) {
	if img, ok := i.images[h]; ok {
		return img, nil
	}

	return nil, fmt.Errorf("image not found: %v", h)
}

func (i *multiArchIndex) ImageIndex(h v1.Hash) (v1.ImageIndex, error) {
	return nil, fmt.Errorf("image not found: %v", h)
}
