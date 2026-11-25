package oci

import (
	"context"
	"sort"
	"sync"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Node sources describe how a tree node was discovered.
const (
	SourceSubject   = "subject"
	SourceReferrer  = "referrer"
	SourceCosignTag = "cosign-tag"
	SourcePlatform  = "platform"
)

// TreeNode is one entry of a supply chain tree.
type TreeNode struct {
	Descriptor ocispec.Descriptor
	Kind       Kind
	Source     string
	// Label is a human readable name: the platform for index entries, the
	// tag for cosign legacy tags.
	Label    string
	Children []*TreeNode
	// Err is set when the children of this node could not be listed.
	Err error
}

// TreeOptions controls how deep ReferrerTree walks.
type TreeOptions struct {
	// MaxDepth limits recursion into referrers of referrers. Defaults to 3.
	MaxDepth int
	// Tags of the repository, used to find cosign legacy tags. If nil, the
	// tags are listed from the registry.
	Tags []string
	// SkipPlatforms disables walking the entries of an index subject.
	SkipPlatforms bool
	// Concurrency limits parallel requests. Defaults to 4.
	Concurrency int
}

// ReferrerTree builds the tree of everything attached to subject: referrers
// (recursively), cosign legacy tags and, for an index, the referrers of each
// platform manifest.
func (c *Client) ReferrerTree(ctx context.Context, repo string, subject ocispec.Descriptor, opts TreeOptions) (*TreeNode, error) {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 3
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.Tags == nil {
		tags, err := c.Tags(ctx, repo)
		if err != nil {
			return nil, err
		}
		opts.Tags = tags
	}

	w := &treeWalker{c: c, repo: repo, opts: opts, sem: make(chan struct{}, opts.Concurrency)}
	root := &TreeNode{Descriptor: subject, Kind: ClassifyDescriptor(subject), Source: SourceSubject}
	w.attach(ctx, root, 1)

	if IsIndexMediaType(subject.MediaType) && !opts.SkipPlatforms {
		idx, err := c.FetchManifest(ctx, repo, subject)
		if err != nil {
			root.Err = err
			return root, nil
		}
		root.Kind = ClassifyManifest(idx)
		platforms := make([]*TreeNode, len(idx.Manifests))
		var wg sync.WaitGroup
		for i, d := range idx.Manifests {
			label := PlatformString(d.Platform)
			if d.Annotations[AnnotationDockerReferenceType] == "attestation-manifest" {
				label = "buildx attestation"
			}
			n := &TreeNode{Descriptor: d, Kind: ClassifyDescriptor(d), Source: SourcePlatform, Label: label}
			platforms[i] = n
			wg.Add(1)
			go func() {
				defer wg.Done()
				w.attach(ctx, n, 1)
			}()
		}
		wg.Wait()
		root.Children = append(root.Children, platforms...)
	}
	return root, nil
}

type treeWalker struct {
	c    *Client
	repo string
	opts TreeOptions
	sem  chan struct{}
}

// attach lists referrers and cosign tags of n and recurses into them.
func (w *treeWalker) attach(ctx context.Context, n *TreeNode, depth int) {
	if depth > w.opts.MaxDepth || ctx.Err() != nil {
		return
	}

	w.sem <- struct{}{}
	refs, err := w.c.Referrers(ctx, w.repo, n.Descriptor)
	<-w.sem
	if err != nil {
		n.Err = err
	}
	sort.SliceStable(refs, func(i, j int) bool {
		ki, kj := ClassifyDescriptor(refs[i]), ClassifyDescriptor(refs[j])
		if ki != kj {
			return ki < kj
		}
		return created(refs[i]) < created(refs[j])
	})

	var children []*TreeNode
	for _, r := range refs {
		children = append(children, &TreeNode{Descriptor: r, Kind: ClassifyDescriptor(r), Source: SourceReferrer})
	}

	for _, st := range CosignTagsFor(n.Descriptor.Digest, w.opts.Tags) {
		child := &TreeNode{Kind: st.Kind, Source: SourceCosignTag, Label: st.Tag}
		w.sem <- struct{}{}
		desc, err := w.c.Resolve(ctx, w.repo, st.Tag)
		<-w.sem
		if err != nil {
			child.Err = err
		} else {
			child.Descriptor = desc
		}
		children = append(children, child)
	}

	var wg sync.WaitGroup
	for _, child := range children {
		if child.Source != SourceReferrer {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.attach(ctx, child, depth+1)
		}()
	}
	wg.Wait()
	n.Children = append(n.Children, children...)
}

func created(d ocispec.Descriptor) string {
	return d.Annotations[ocispec.AnnotationCreated]
}

// FlatNode is a TreeNode with its rendered tree prefix, ready for a table.
type FlatNode struct {
	Node   *TreeNode
	Depth  int
	Prefix string
}

// Flatten renders the tree depth-first with box-drawing prefixes. The root
// is included with an empty prefix.
func (n *TreeNode) Flatten() []FlatNode {
	out := []FlatNode{{Node: n}}
	var walk func(n *TreeNode, depth int, indent string)
	walk = func(n *TreeNode, depth int, indent string) {
		for i, child := range n.Children {
			last := i == len(n.Children)-1
			branch, next := "├─ ", "│  "
			if last {
				branch, next = "└─ ", "   "
			}
			out = append(out, FlatNode{Node: child, Depth: depth, Prefix: indent + branch})
			walk(child, depth+1, indent+next)
		}
	}
	walk(n, 1, "")
	return out
}

// Count returns the number of nodes below n.
func (n *TreeNode) Count() int {
	total := 0
	for _, c := range n.Children {
		total += 1 + c.Count()
	}
	return total
}
