#!/usr/bin/env bash
# Compile Opti-PC.exe pour Windows 64 bits (fonctionne depuis Linux, macOS ou Windows/Git Bash).
# Prérequis : Go >= 1.22  et  go install github.com/tc-hib/go-winres@latest
set -euo pipefail
cd "$(dirname "$0")"

WINRES="$(go env GOPATH)/bin/go-winres"
# Icône + manifeste (demande automatique des droits administrateur)
"$WINRES" make --arch amd64 --in winres/winres.json --out rsrc

mkdir -p dist
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/Opti-PC.exe .
echo "OK -> dist/Opti-PC.exe"
