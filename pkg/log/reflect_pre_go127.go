// Copyright (C) 2026  mieru authors
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

//go:build !go1.27

package log

import "reflect"

// pointerKind is the reflect kind of a pointer. The value is defined per
// toolchain version, so it can't be inlined at the use sites.
//
//nolint:govet // govet wants reflect.Ptr inlined, which would defeat the version split.
const pointerKind = reflect.Ptr
