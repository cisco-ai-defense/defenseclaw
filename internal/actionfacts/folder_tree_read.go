// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

// ReadsFolderTree reports a command that reads each folder it reads with
// every file below it: a tar create (tar recurses into its member folders
// unless --no-recursion), zip -r, cp -r, -R or -a, and rsync -r or -a. Its
// read of a folder is a read of every file the folder holds, which the
// gateway judges as the read of the credentials files of a credentials
// folder (CredentialFolderTreeHolds, substrate-1:GAP-0995). cp without -r,
// rsync -d and zip without -r take no file below a folder operand.
func ReadsFolderTree(command CommandFact) bool {
	if command.Effect != EffectExecute || len(command.Argv) < 2 {
		return false
	}
	switch strings.ToLower(command.Program) {
	case "tar", "tar.exe", "gtar", "bsdtar":
		if !hasFactOperation(command, OperationRead) {
			return false // a tar that reads members is a create (classifyTarArchiveProducer)
		}
		for _, arg := range command.Argv[1:] {
			if arg == "--" {
				break
			}
			if arg == "--no-recursion" {
				return false
			}
		}
		return true
	case "zip", "zip.exe":
		_, recursive := parseZipOptions(command.Argv).seen["-r"]
		return recursive
	case "rsync":
		seen := parseRsyncOptions(command.Argv).seen
		for _, option := range []string{"-r", "-a", "--recursive", "--archive"} {
			if _, ok := seen[option]; ok {
				return true
			}
		}
		return false
	case "cp":
		return command.Dialect != DialectPowerShell && posixCopyRecursive(command.Argv)
	}
	return false
}

// posixCopyRecursive reports a cp argv (the program word first) with -r, -R,
// -a, --recursive or --archive among its options. The values of -t and -S
// (and of their long forms) are no options.
func posixCopyRecursive(argv []string) bool {
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--":
			return false
		case arg == "-" || !strings.HasPrefix(arg, "-"):
			continue
		case strings.HasPrefix(arg, "--"):
			switch arg {
			case "--recursive", "--archive":
				return true
			case "--target-directory", "--suffix":
				i++
			}
			continue
		}
		for offset := 1; offset < len(arg); offset++ {
			switch arg[offset] {
			case 'r', 'R', 'a':
				return true
			case 't', 'S':
				if offset+1 == len(arg) {
					i++
				}
				offset = len(arg)
			}
		}
	}
	return false
}

// credentialFolderTree is one folder that holds a credentials file of the
// table: folder is the folder of the file (the parent of a trailing relative
// path, a row dir, a row folder), tool the folder of the tool it belongs to
// (.aws for .aws/sso/cache, .config/gcloud for .config/gcloud/legacy_credentials).
type credentialFolderTree struct {
	tool, folder string
	class        CredentialFileClass
}

// credentialSharedHomeFolders are the home folders that hold the folders of
// many tools (the XDG roots, the Windows and macOS application-data roots),
// not the files of one: an archive of one is a backup of every setting, not
// a read of one credentials folder.
var credentialSharedHomeFolders = map[string]bool{
	".config": true, ".cache": true, ".local": true, ".local/share": true, ".local/state": true,
	"appdata": true, "appdata/roaming": true, "appdata/local": true,
	"library": true, "library/application support": true,
}

// credentialFolderTrees are the home-relative credentials folders of the
// credentials-file table, built from it so a row added to the table is read
// here with no edit. A tool folder is a dot folder of the home or a folder of
// an application-data root: a row whose folder is neither (the runtime
// containers/auth.json, the system etc/ and var/ rows) names no folder of a
// home, and a row with notFolder (.claude) holds settings, not a login.
var credentialFolderTrees = func() []credentialFolderTree {
	var trees []credentialFolderTree
	add := func(class CredentialFileClass, folder string) {
		if folder == "" || folder == "." {
			return
		}
		tool := ""
		for _, part := range strings.Split(folder, "/") {
			if tool == "" {
				tool = part
			} else {
				tool += "/" + part
			}
			if !credentialSharedHomeFolders[tool] {
				break
			}
		}
		if credentialSharedHomeFolders[tool] {
			return
		}
		if first, _, _ := strings.Cut(tool, "/"); !strings.HasPrefix(first, ".") && !credentialSharedHomeFolders[first] {
			return
		}
		trees = append(trees, credentialFolderTree{tool: tool, folder: folder, class: class})
	}
	for _, row := range credentialFileShapes {
		switch {
		case row.relative != "":
			if strings.Contains(row.relative, "/") && !row.notFolder {
				add(row.class, path.Dir(row.relative))
			}
		case row.folder != "":
			add(row.class, row.folder)
		case row.dir != "":
			add(row.class, row.dir)
		}
	}
	return trees
}()

// CredentialFolderTreeHolds reports a home-relative folder (lower case,
// forward slashes, cleaned) whose tree holds a credentials file of class: the
// folder of the file or a folder between it and the tool folder (.aws holds
// .aws/credentials, .config/gcloud holds its credentials.db). The home (""),
// a shared root (.config), a folder below the file (.config/gcloud/configurations)
// and a folder of another name (proj/.aws) hold none.
func CredentialFolderTreeHolds(folder string, class CredentialFileClass) bool {
	folder = strings.Trim(folder, "/")
	if folder == "" || folder == "." {
		return false
	}
	for _, tree := range credentialFolderTrees {
		if tree.class == class &&
			(folder == tree.folder || strings.HasPrefix(tree.folder, folder+"/")) &&
			(folder == tree.tool || strings.HasPrefix(folder, tree.tool+"/")) {
			return true
		}
	}
	return false
}
