# x64dbgbinja

Official x64dbg plugin for [Binary Ninja](https://binary.ninja).

## Installation

From the Plugins Menu, select "Manage Plugins". Search for "x64dbgbinja" and click the "Install" button.

## Menu options

### Import database

Import comments/labels from an uncompressed x64dbg JSON database in Binary Ninja.

Symbols for imported functions and or library functions can be overwritten via the "Overwrite X" entries in Settings.

### Export database

Export comments/labels to a JSON database that can be loaded by x64dbg.

To export labels only: uncheck "Export Comments" under "x64dbg Database Export" in Settings.
