//go:build !linux

package agent

import "os"

func runtimeProcessHasArg(string, string) bool { return false }

func runtimeProcessMapsBinary(string, string, os.FileInfo) (bool, bool) { return false, false }
