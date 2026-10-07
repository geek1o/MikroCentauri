package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

var appProvisionFiles = map[string]bool{
	"app.json": true, "model.json": true, "runtime.json": true, "profile.json": true,
	"router.json": true, "server.crt": true, "server.key": true, "api.crt": true,
	"api.key": true, "ca.crt": true, "router-ca.crt": true, "router.crt": true, "password": true,
}

// Provisioning is deliberately separate from normal startup: a missing config
// never causes network downloads, guessed credentials or an authentication reset.
func decodeAppProvisionArchive(data []byte) (map[string][]byte, error) {
	files := map[string][]byte{}
	reader := tar.NewReader(bytes.NewReader(data))
	var total int64
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("invalid provisioning archive")
		}
		name := filepath.Base(header.Name)
		if header.Name != "bootstrap/"+name || !appProvisionFiles[name] || files[name] != nil || (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) || header.Mode != 0600 || header.Size < 1 || header.Size > 4<<20 || len(header.PAXRecords) != 0 {
			return nil, errors.New("provisioning archive requires unique allowlisted private regular files")
		}
		total += header.Size
		if total > 8<<20 {
			return nil, errors.New("provisioning archive contents exceed limit")
		}
		content, err := io.ReadAll(io.LimitReader(reader, (4<<20)+1))
		if err != nil || int64(len(content)) != header.Size {
			return nil, errors.New("invalid provisioning file contents")
		}
		files[name] = content
	}
	if files["app.json"] == nil {
		return nil, errors.New("provisioning archive requires bootstrap/app.json")
	}
	return files, nil
}

// Image volumes may materialize the image's empty bootstrap directory. It is
// the only preexisting child provisioning accepts; durable contents stay denied.
func appProvisionEmptyVolume(dataDirectory string) (os.FileInfo, error) {
	entries, err := os.ReadDir(dataDirectory)
	if err != nil || len(entries) > 1 {
		return nil, errors.New("provisioning requires an empty data volume or its sole empty bootstrap directory")
	}
	if len(entries) == 0 {
		return nil, nil
	}
	if entries[0].Name() != "bootstrap" {
		return nil, errors.New("provisioning refuses existing data volume entries")
	}
	path := filepath.Join(dataDirectory, "bootstrap")
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("preexisting bootstrap must be a real empty directory")
	}
	children, err := os.ReadDir(path)
	if err != nil || len(children) != 0 {
		return nil, errors.New("provisioning refuses existing bootstrap contents")
	}
	return info, nil
}

func provisionAppArchive(archivePath, dataDirectory string) error {
	if !canonicalAppPath(archivePath) || !canonicalAppPath(dataDirectory) || archivePath == dataDirectory || beneathAppData(dataDirectory, archivePath) {
		return errors.New("private archive must be outside canonical data directory")
	}
	data, err := readRouterFile(archivePath, 9<<20, true)
	if err != nil {
		return err
	}
	defer clear(data)
	files, err := decodeAppProvisionArchive(data)
	if err != nil {
		return err
	}
	defer func() {
		for _, content := range files {
			clear(content)
		}
	}()
	// Every parent must be a real directory. Never follow a mounted symlink
	// into an existing instance while checking an apparently empty volume.
	for directory := dataDirectory; ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("provisioning data directory must exist without symlinks")
		}
		if filepath.Dir(directory) == directory {
			break
		}
	}
	previousBootstrap, err := appProvisionEmptyVolume(dataDirectory)
	if err != nil {
		return err
	}
	info, err := os.Lstat(dataDirectory)
	if err != nil {
		return errors.New("provisioning data directory unavailable")
	}
	// Validate a protected complete staging bundle before touching the volume.
	stage, err := os.MkdirTemp("", "mikrocentauri-provision-")
	if err != nil {
		return errors.New("private provisioning staging unavailable")
	}
	defer os.RemoveAll(stage)
	stage, err = filepath.EvalSymlinks(stage)
	if err != nil {
		return errors.New("private provisioning staging unavailable")
	}
	bootstrap := filepath.Join(stage, "bootstrap")
	if err = os.Mkdir(bootstrap, 0700); err != nil {
		return errors.New("private provisioning staging unavailable")
	}
	for name, content := range files {
		file, err := os.OpenFile(filepath.Join(bootstrap, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("private provisioning staging write failed")
		}
		_, writeErr := file.Write(content)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return errors.New("private provisioning staging write failed")
		}
	}
	settings, _, _, err := appInstallInputs(filepath.Join(bootstrap, "app.json"), stage, time.Now())
	if err != nil {
		return err
	}
	if settings.PasswordFile != "/data/bootstrap/password" {
		return errors.New("first provisioning requires canonical bootstrap password file")
	}
	password := files["password"]
	if len(password) > 0 && password[len(password)-1] == '\n' {
		password = password[:len(password)-1]
	}
	if len(password) < 16 || len(password) > 1024 {
		return errors.New("provisioning password must contain 16 to 1024 bytes")
	}
	// Create the publication directory exclusively; rollback removes only paths
	// this invocation created. The caller must keep App and other admins stopped.
	currentBootstrap, err := appProvisionEmptyVolume(dataDirectory)
	if err != nil || (previousBootstrap == nil) != (currentBootstrap == nil) || (previousBootstrap != nil && !os.SameFile(previousBootstrap, currentBootstrap)) {
		return errors.New("provisioning volume changed while validating inputs")
	}
	if err = os.Chmod(dataDirectory, 0700); err != nil {
		return errors.New("private data volume mode cannot be established")
	}
	published := filepath.Join(dataDirectory, "bootstrap")
	if previousBootstrap == nil {
		err = os.Mkdir(published, 0700)
	} else {
		err = os.Chmod(published, 0700)
	}
	if err != nil {
		_ = os.Chmod(dataDirectory, info.Mode())
		return errors.New("provisioning publication already exists")
	}
	created := []string{}
	committed := false
	defer func() {
		if !committed {
			for _, path := range created {
				_ = os.Remove(path)
			}
			if previousBootstrap == nil {
				_ = os.Remove(published)
			} else {
				_ = os.Chmod(published, previousBootstrap.Mode())
			}
			_ = os.Chmod(dataDirectory, info.Mode())
		}
	}()
	names := make([]string, 0, len(files))
	for name := range files {
		if name != "app.json" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	// Configuration is the startup gate. Publish it only after all dependencies
	// are synced, so interrupted provisioning never exposes a partial bundle.
	names = append(names, "app.json")
	for _, name := range names {
		content := files[name]
		path := filepath.Join(published, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("provisioning publication refuses overwrite")
		}
		created = append(created, path)
		_, writeErr := file.Write(content)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return errors.New("provisioning publication write failed")
		}
	}
	directory, err := os.Open(published)
	if err != nil {
		return errors.New("provisioning publication sync failed")
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("provisioning publication sync failed")
	}
	committed = true
	return nil
}

func appProvisionCommand(args []string) error {
	fs := flag.NewFlagSet("app-provision", flag.ContinueOnError)
	archive := fs.String("archive", "", "protected0400/0600 bounded native bootstrap tar outside /data")
	data := fs.String("data", "/data", "existing empty persistent data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *archive == "" {
		return errors.New("app-provision requires archive and no positional arguments")
	}
	if err := provisionAppArchive(*archive, *data); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"protected_bundle_installed": true, "authentication_initialized": false, "readiness": false, "scope": "one-time empty volume provisioning; clear temporary command override then review and verify stopped App identity"})
}
