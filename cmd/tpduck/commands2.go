package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nexusriot/tpduck/internal/agent"
	"github.com/nexusriot/tpduck/internal/model"
)

// --- agent ---

func cmdAgent(f *flags, path string, args []string) error {
	action := "status"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "run":
		ttl := f.agentTTL
		if ttl <= 0 {
			ttl = agent.DefaultTTL
		}
		fmt.Fprintf(os.Stderr, "tpduck agent listening on %s (keys expire after %s)\n", agent.SocketPath(), ttl)
		return agent.Serve(agent.SocketPath(), ttl)
	case "status":
		n, err := agent.Status()
		if err != nil {
			fmt.Println("no agent running")
			return nil
		}
		fmt.Printf("agent running on %s, holding %d key(s)\n", agent.SocketPath(), n)
		return nil
	case "stop":
		if err := agent.StopAgent(); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "agent stopped")
		return nil
	case "forget":
		// With no argument this drops every key, which is what you want when
		// stepping away from the machine.
		target := ""
		if len(args) > 1 {
			target = path
		}
		if err := agent.Drop(target); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "forgotten")
		return nil
	default:
		return errors.New("usage: tpduck agent <run|status|stop|forget>")
	}
}

// --- profiles ---

func cmdProfiles() error {
	profiles, err := model.ListProfiles()
	if err != nil {
		return err
	}
	for _, p := range profiles {
		state := fmt.Sprintf("%d accounts", p.Accounts)
		if p.Encrypted {
			state = "encrypted"
		}
		fmt.Printf("%-16s  %-10s  %s\n", p.Name, state, p.Path)
	}
	fmt.Fprintln(os.Stderr, "\nuse a profile with: tpduck -p <name> ...")
	return nil
}

// --- tags ---

func cmdTag(f *flags, path string, args []string) error {
	if len(args) == 0 {
		store, key, err := openVault(f, path)
		if err != nil {
			return err
		}
		defer key.Zero()
		tags := store.Tags()
		if len(tags) == 0 {
			fmt.Fprintln(os.Stderr, "no tags in use")
			return nil
		}
		for _, t := range tags {
			fmt.Println(t)
		}
		return nil
	}
	if len(args) < 2 {
		return errors.New("usage: tpduck tag <query> <tag,tag,...>   (empty string clears)")
	}
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	acc, err := store.Find(args[0])
	if err != nil {
		return err
	}
	var tags []string
	if strings.TrimSpace(args[1]) != "" {
		tags = strings.Split(args[1], ",")
	}
	if err := store.SetTags(acc.ID, tags); err != nil {
		return err
	}
	if err := saveVault(store, path, key); err != nil {
		return err
	}
	updated, _ := store.Find(acc.ID)
	if len(updated.Tags) == 0 {
		fmt.Printf("%s: tags cleared\n", acc.Label())
		return nil
	}
	fmt.Printf("%s: %s\n", acc.Label(), strings.Join(updated.Tags, ", "))
	return nil
}

// --- retained versions ---

func cmdVersions(path string) error {
	versions, err := model.Versions(path)
	if err != nil {
		return err
	}
	if len(versions) == 0 {
		fmt.Fprintln(os.Stderr, "no retained versions yet (one is kept before each save)")
		return nil
	}
	for _, v := range versions {
		state := "plaintext"
		if v.Encrypted {
			state = "encrypted"
		}
		fmt.Printf("%d  %-10s  %6d bytes  %s\n", v.N, state, v.Size, v.Modified.Format(time.RFC3339))
	}
	fmt.Fprintf(os.Stderr, "\nrestore one with: tpduck undo -version <n>\n")
	return nil
}

func cmdRestoreVersion(f *flags, path string, args []string) error {
	n := f.version
	if n == 0 && len(args) > 0 {
		if _, err := fmt.Sscanf(args[0], "%d", &n); err != nil {
			return fmt.Errorf("version must be a number")
		}
	}
	if n == 0 {
		n = 1 // "undo" means the most recent copy
	}
	versions, err := model.Versions(path)
	if err != nil {
		return err
	}
	var target *model.Version
	for i := range versions {
		if versions[i].N == n {
			target = &versions[i]
		}
	}
	if target == nil {
		return fmt.Errorf("no retained version %d (try: tpduck versions)", n)
	}
	ok, err := confirm(f.force, fmt.Sprintf("Replace the vault with version %d from %s?",
		target.N, target.Modified.Format(time.RFC3339)))
	if err != nil || !ok {
		fmt.Fprintln(os.Stderr, "not restored")
		return nil
	}
	if err := model.RestoreVersion(path, n); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "restored version %d; the previous vault is now version 1\n", n)
	return nil
}
