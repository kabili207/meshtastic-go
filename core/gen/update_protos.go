package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"golang.org/x/mod/semver"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"

	//lint:ignore ST1001 looks better with dot imports
	. "github.com/dave/jennifer/jen"
)

var (
	protoOutDir = "proto"
)

func main() {
	status, tag, commit := updateProtobufRepo()
	makeVersionFile(status, tag, commit)

	// This must be relative to the project root (which is core/)
	protoInDir := "../protobufs/"

	// Upstream's protos don't generate valid Go on their own, so build from a patched
	// copy rather than mutating the submodule. See stageProtos.
	staged, err := stageProtos(protoInDir)
	if err != nil {
		fmt.Printf("failed to stage protos: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(staged)
	protoInDir = staged

	// Clean up any previous generated directory (protoc creates "generated" based on go_package)
	os.RemoveAll("generated")

	// Use module option to strip the meshtastic module prefix from go_package.
	// Proto files have: go_package = "github.com/meshtastic/go/generated"
	// With module=github.com/meshtastic/go, output goes to ./generated/
	args := []string{
		"-I", protoInDir,
		"--go_out=.",
		"--go_opt=module=github.com/meshtastic/go",
	}
	t := find(protoInDir, ".proto")
	args = append(args, t...)

	cmd := exec.Command("protoc", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("protoc failed: %s\n", err)
		os.Exit(1)
	}

	// Rename package from "generated" to "proto" in all generated files
	if err := fixPackageName("generated", protoOutDir); err != nil {
		fmt.Printf("failed to fix package names: %s\n", err)
		os.Exit(1)
	}

	// Move generated files to proto directory
	if err := moveGeneratedFiles("generated", protoOutDir); err != nil {
		fmt.Printf("failed to move files: %s\n", err)
		os.Exit(1)
	}

	// Clean up the generated directory
	os.RemoveAll("generated")

	fmt.Println("Protobufs generated successfully")
}

// fixPackageName replaces "package generated" with "package proto" in all .go files
func fixPackageName(srcDir, pkgName string) error {
	return filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Replace package declaration
		newContent := bytes.Replace(content, []byte("package generated"), []byte("package "+pkgName), 1)

		if err := os.WriteFile(path, newContent, 0644); err != nil {
			return err
		}

		return nil
	})
}

// moveGeneratedFiles moves .pb.go files from srcDir to dstDir
func moveGeneratedFiles(srcDir, dstDir string) error {
	return filepath.WalkDir(srcDir, func(srcPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(srcPath) != ".go" {
			return nil
		}

		dstPath := filepath.Join(dstDir, filepath.Base(srcPath))
		if err := os.Rename(srcPath, dstPath); err != nil {
			return err
		}

		return nil
	})
}

// protoPatch rewrites a single proto source before it reaches protoc.
type protoPatch struct {
	file string
	old  string
	new  string
}

// protoPatches works around upstream protos that generate Go which doesn't compile.
// Drop entries here as they're fixed upstream; an entry that no longer applies is a
// hard error rather than a silent no-op.
//
// admin.proto's AS3935_config and telemetry.proto's AS3935Config are distinct protobuf
// names, so protoc accepts both, but protoc-gen-go mangles them to the same Go
// identifier. Every generated file shares one package (go_package is identical across
// upstream's protos), so the two collide and the package won't build.
//
// Renaming the message also renames it in the descriptor, but nothing observable moves:
// a nested message field carries no type name on the wire, and the field itself keeps
// its number (7) and its name (as3935_config), so both the binary and JSON encodings are
// byte-identical to upstream. Only Any/type-URL lookups would notice, and nothing here
// uses them.
var protoPatches = []protoPatch{
	{file: "meshtastic/admin.proto", old: "AS3935_config", new: "AS3935AdminConfig"},
}

// stageProtos copies the proto tree to a temporary directory and applies protoPatches
// to the copy, leaving the submodule checkout untouched. Returns the staging directory.
func stageProtos(srcDir string) (string, error) {
	stageDir, err := os.MkdirTemp("", "meshtastic-protos-")
	if err != nil {
		return "", err
	}

	for _, src := range find(srcDir, ".proto") {
		rel, err := filepath.Rel(srcDir, src)
		if err != nil {
			return "", err
		}
		content, err := os.ReadFile(src)
		if err != nil {
			return "", err
		}

		for _, p := range protoPatches {
			if filepath.ToSlash(rel) != p.file {
				continue
			}
			if !bytes.Contains(content, []byte(p.old)) {
				return "", fmt.Errorf("patch for %s no longer applies: %q not found (fixed upstream? remove it)", p.file, p.old)
			}
			content = bytes.ReplaceAll(content, []byte(p.old), []byte(p.new))
		}

		dst := filepath.Join(stageDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return "", err
		}
		if err := os.WriteFile(dst, content, 0644); err != nil {
			return "", err
		}
	}

	return stageDir, nil
}

func find(root, ext string) []string {
	var a []string
	filepath.WalkDir(root, func(s string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if filepath.Ext(d.Name()) == ext {
			a = append(a, s)
		}
		return nil
	})
	return a
}

func updateProtobufRepo() (git.Status, *plumbing.Reference, *object.Commit) {
	repo, err := git.PlainOpen("../protobufs")
	if err != nil {
		panic(fmt.Errorf("failed to open git repository: %w", err))
	}

	err = repo.Fetch(&git.FetchOptions{RemoteName: "origin"})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		panic(fmt.Errorf("failed to fetch latest protobufs: %w", err))
	}

	tagIter, err := repo.Tags()

	if err != nil {
		panic(fmt.Errorf("failed to retrieve tag information: %w", err))
	}
	versionTags := []string{}
	err = tagIter.ForEach(func(t *plumbing.Reference) error {
		if semver.IsValid(t.Name().Short()) {
			versionTags = append(versionTags, t.Name().Short())
		}
		return nil
	})
	if err != nil {
		panic(fmt.Errorf("failed to parse tags: %w", err))
	}

	semver.Sort(versionTags)
	latestTag, err := repo.Tag(versionTags[len(versionTags)-1])

	if err != nil {
		panic(fmt.Errorf("failed to get latest tag: %w", err))
	}
	worktree, err := repo.Worktree()
	if err != nil {
		panic(fmt.Errorf("failed to get git worktree: %w", err))
	}

	err = worktree.Checkout(&git.CheckoutOptions{Hash: latestTag.Hash()})
	if err != nil {
		panic(fmt.Errorf("failed to get latest tag: %w", err))
	}

	repoCommit, err := repo.CommitObject(latestTag.Hash())
	if err != nil {
		panic(fmt.Errorf("failed to get git commit: %w", err))
	}

	worktreeStatus, err := worktree.Status()
	if err != nil {
		panic(fmt.Errorf("failed to get git worktree status: %w", err))
	}

	return worktreeStatus, latestTag, repoCommit
}

func makeVersionFile(worktreeStatus git.Status, repoHead *plumbing.Reference, repoCommit *object.Commit) {
	f := NewFilePath(protoOutDir)

	f.HeaderComment("Code generated by gen/update_protos.go - DO NOT EDIT.")

	f.Const().Id("ProtobufDirty").Op("=").Lit(!worktreeStatus.IsClean())
	f.Const().Id("ProtobufSha").Op("=").Lit(repoHead.Hash().String())
	f.Const().Id("ProtobufTimestamp").Op("=").Lit(repoCommit.Author.When.Unix())
	f.Const().Id("ProtobufVersion").Op("=").Lit(repoHead.Name().Short())

	f.Func().Id("ProtobufTime").Params().Qual("time", "Time").Block(
		Return(Qual("time", "Unix").Call(Id("ProtobufTimestamp"), Lit(0))),
	)

	f.Func().Id("ProtobufDisplayVersion").Params().String().Block(
		Id("ver").Op(":=").Qual("fmt", "Sprintf").Params(
			Lit("%s-%s"),
			Id("ProtobufVersion"),
			Id("ProtobufSha").Index(Empty(), Lit(8)),
		),
		If(Id("ProtobufDirty")).Block(
			Id("ver").Op("=").Qual("fmt", "Sprintf").Params(Lit("%s-dirty"), Id("ver")),
		),
		Return(Id("ver")),
	)

	file := path.Join(protoOutDir, "version.go")
	fmt.Printf("saving file %v\n", file)
	if err := f.Save(file); err != nil {
		panic(fmt.Errorf("failed to save file: %w", err))
	}
}
