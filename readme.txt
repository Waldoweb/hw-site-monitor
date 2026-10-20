=== HW Site Monitor ===
Contributors: hostetlerweb
Requires at least: 5.6
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPL-2.0-or-later

Read-only report for the Hostetler Web dashboard.

== Description ==

Adds one REST endpoint, GET /wp-json/hw-monitor/v1/report, that answers only requests signed by the Hostetler Web dashboard (Ed25519; the public key is in public-keys.php, the private key only in the dashboard). It reports WordPress, PHP, plugin and theme versions, pending updates as WordPress last checked them, and which Independent Analytics tables exist.

There are no settings and no key to enter: installing it is the whole setup. Answering a request changes nothing on the site. Updates install automatically from GitHub releases.

== Changelog ==

= 1.0.0 =
* First release: signed, read-only report of versions, plugins, themes and pending updates; Independent Analytics table discovery.
