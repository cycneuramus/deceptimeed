# Package

version = "1.1.2" # x-release-please-version
author = "cycneuramus"
description = "Loads IP blocklists into nftables from plain text or JSON feeds"
license = "AGPL-3.0-only"
srcDir = "src"
bin = @["deceptimeed"]

# Dependencies

requires "nim >= 2.2.2"

requires "argparse >= 4.0.2"
