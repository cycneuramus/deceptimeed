# Package

version = "0.1.0"
author = "cycneuramus"
description = "Loads IP blocklists into nftables from plain text or JSON feeds"
license = "AGPL-3.0-only"
srcDir = "src"
bin = @["deceptimeed"]

# Dependencies

requires "nim >= 2.0.0"

task build, "Builds the project with SSL support":
  exec "nim c -d:release -d:ssl src/deceptimeed.nim"
