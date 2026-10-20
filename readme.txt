=== HW Site Monitor ===
Contributors: hostetlerweb
Requires at least: 5.6
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPL-2.0-or-later

Read-only report for the Hostetler Web dashboard.

== Description ==

Adds one REST endpoint, GET /wp-json/hw-monitor/v1/report, that answers only requests signed by the Hostetler Web dashboard (Ed25519; the public key is in public-keys.php, the private key only in the dashboard). It reports WordPress, PHP, plugin and theme versions and pending updates as WordPress last checked them. With ?from=&to= (up to 31 days) it adds Independent Analytics daily visitors, sessions and views, form submissions, orders and link clicks; with &tops=1 also top pages, channels, referrers and UTM campaigns. Days follow the site's own timezone.

There are no settings and no key to enter: installing it is the whole setup. Answering a request changes nothing on the site. Updates install automatically from GitHub releases.

== Changelog ==

= 1.1.0 =
* Independent Analytics traffic: daily visitors, sessions and views; form submissions by form, orders (count and order value) and link clicks; top pages, channels, referrers and UTM campaigns. Read from IA's tables with a few summary queries, counted in the site's timezone.
* Checks every IA column it reads first, so an IA update that changes its tables gets "unsupported" instead of wrong numbers. Checked against IA Pro 2.16.1 (database 53).
* Traffic requests sign their date range too.

= 1.0.0 =
* First release: signed, read-only report of versions, plugins, themes and pending updates; Independent Analytics table discovery.
