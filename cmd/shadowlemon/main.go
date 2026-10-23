// Copyright (C) 2021  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Binary shadowlemon is the unified client and server of the ShadowLemon proxy.
//
// The first argument selects the mode, either "client" or "server".
package main

import (
	"os"
	"runtime/debug"

	"github.com/Acheirial/shadowlemon/v3/pkg/appctl"
	"github.com/Acheirial/shadowlemon/v3/pkg/cli"
	"github.com/Acheirial/shadowlemon/v3/pkg/log"
)

func main() {
	setLogPrefix()
	appctl.RecordAppStartTime()
	debug.SetGCPercent(90)
	cli.RegisterClientCommands()
	cli.RegisterServerCommands()
	if err := cli.ParseAndExecute(); err != nil {
		log.Fatalf("%v", err)
	}
}

// setLogPrefix sets the daemon log prefix based on the selected mode, so that
// the client logs start with "C" and the server logs start with "S".
func setLogPrefix() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case "client":
		log.LogPrefix = "C"
	case "server":
		log.LogPrefix = "S"
	}
}
