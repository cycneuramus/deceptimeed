# Package

version = "0.1.1" # x-release-please-version
author = "cycneuramus"
description = "Loads IP blocklists into nftables from plain text or JSON feeds"
license = "AGPL-3.0-only"
srcDir = "src"
bin = @["deceptimeed"]

# Dependencies

requires "nim >= 2.0.0"
