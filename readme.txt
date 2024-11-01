=== tinyShield - Simple. Focused. Security. ===
Contributors: adamsewell
Donate link: https://tinyshield.me
Tags: security, blocklist, brute force, bruteforce, spam, waf, firewall
Requires at least: 5.3
Tested up to: 5.9
Stable tag: 1.1.1
Requires PHP: 5.6.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Fast, effective, realtime, and crowd sourced protection for WordPress. Easily block bots, brute force attempts, exploits and more without bloat.

== Description ==
tinyShield is a security plugin for any WordPress site. It will monitor all incoming and outgoing connections to your site and block any malicious traffic that it identifies. It does this by tapping into our network of other WordPress sites that report malicious activity. Think herd immunity. The future of WordPress security is crowd sourced.

<strong>A note to developers, only activate/register sites once they are on their final domains. If you alter the domain after you have activated it, tinyShield will not work correctly.</strong>

There are two subscription levels tinyShield can use. By default all installs have access to community features.

= Community Features =
* Simple Interface
* Focused On Protection
* Pretty Deny Page
* Crowd Sourced Blocklist
* Automatic Search Engine Crawler Detection
* Manually Reviewed Lists
* Automatic Brute Force Protection
* Automatic User Enumeration Protection
* Automatic Registration Spam Prevention (Honeypot)
* User Defined Allowlist
* User Defined Blocklist
* IPv4 and IPv6 Support
* 404 Reporting
* Free For Life

= Professional Features =
* Tor Exit Node Blocking
* Geographical Information on Visitors
* Cloudflare Integration
* Inclusive Country Blocking
* Exclusive Country Blocking
* Professional Comprehensive Blocklist
* More coming soon...

== Installation ==

This section describes how to install the plugin and get it working.

1. Upload the plugin files to the `/wp-content/plugins/tinyShield` directory, or install the plugin through the WordPress plugins screen directly.
1. Activate the plugin through the 'Plugins' screen in WordPress
1. Use the Settings->tinyShield screen to register and activate the plugin

== Frequently Asked Questions ==

= How do I gain access to the service? =
tinyShield is made up of two components - the WordPress plugin and our servers. The plugin will not function correctly without registering with tinyShield. Registration can be done directly from the Settings tab of tinyShield. There is no cost for the community version of our real time blocklist. You have the option to upgrade to our professional list and gain access to a more comprehensive blocklist.

= What is crowd sourced security? =
tinyShield watches and reports back some information from your site in order to improve our community and premium feeds. For each site that uses tinyShield, even using the community feed, they will contribute back to help the other users of tinyShield.

= How much does it cost? =
There will never be a charge for the community version of this service. Premium access, billed annually, will based on how many sites you want to protect. Subscribing will not only help support the project but also, automatically give you access to our more comprehensive feed that is crowd sourced plus a host of other features.

= What performance impact will this have on my site? =
In our testing, we have noticed no performance issues while using the plugin. If for some reason our servers are unreachable, the plugin will fail open. This means that if our servers are down for any reason, your site will continue to work and utilize the local cached lists.

= Privacy =
While tinyShield collects information from your site, we only collect the offending IP address, failed user login attempts, and the site the attempt was made on (as you can see from examination of the code). These items are only logged to determine patterns. No information we collect will EVER be sold or given to third parties.

This section will always be up-to-date with all information that is reported back to tinyShield. Also, we encourage you to review our source code for accurate information.

= Is tinyShield compatible with caching plugins? =
Currently, caching plugins do not allow tinyShield to function correctly. Because the request hits the cache before tinyShield sees it, tinyShield does not register the request.

= Is tinyShield compatible with other security plugins? =
While tinyShield does not cause any known conflicts with other WordPress security plugins, and can work well alongside them as an extra layer of protection.  It takes a very targeted approach to just real time blocklists. There are however, some plugins that are known to cause tinyShield to not operate normally. They are listed below.

1. wp-spamshield

= Banner Image Credit =
Image credits to: https://unsplash.com/@matthewhenry

== Changelog ==
= 1.1.1 =
* [+] added a new dashboard widget with a fancy graph and latest news.
* [*] fixed a potential error on the tabs
* [*] replaced some functions to be more inline with WordPress functions

= 1.1.0 =
* [+] added support for modules
* [+] added cloudflare module for premium access members
* [+] added immediate (10 tries in 24 hours) block of brute force bots rather than relying on endpoints - still reports each attempt if enabled
* [*] changed current_time timestamp to time in reference https://make.wordpress.org/core/2019/09/23/date-time-improvements-wp-5-3/
* [*] fixed an issue with the options not saving in some instances and added a check to fix options that should be enabled

= 1.0.1 =
* [*] adjusted wording in the review nag to be consistent
* [*] added upgrade notice when blank GeoIP information
* [+] moved certain bot/crawler checking into the plugin to bypass any potential blocking of search engine crawlers - all major global search engines are supported

= 1.0.0 =
* [+] added support for upgrade paths (finally)
* [*] fixed an potential bug that would not remove the subscription on deactivation

= 0.6.3 =
* [*] fixed a potential fatal error if the response from our server is anything other than 200 in logging the response

= 0.6.2 =
* [*] escaped more urls
* [*] added language and code for license key management on tinyshields website
* [+] added new warning if a license key issue is detected from tinyshields side. if detected, it will not go away until the site is deactivated
* [*] fixed an issue when adding the activating ip to the perm allowlist where the ip would not display
* [*] fixed an issue where the review notice would show before the correct time
* [+] added some pretty to the admin notices
* [+] added wording to give access to the tinyShield account on the settings page. This is where you would manage your keys and sites

= 0.6.1 =
* [*] adjusted some items for the new license handling
* [*] adjusted some notices
* [*] adjusted a sanitation function

= 0.6.0 =
* [*] made the site key visible for saving - important for upcoming changes
* [*] replaced the deprecated chosen js library with the select2 js library
* [*] fixed a few undefined index notices
* [*] adjusted the classes used for admin_notices to comply with WordPress standards
* [+] added the ability to report spam comments - enabled by default

= 0.5.5 =
* [*] changed the verbage used to identify the lists. Blocklist and Allowlist will now be used.
* [*] adjusted the upgrade routines to be more reliable and moved them into their own class

= 0.5.4 =
* [+] added a registration honeypot to help combat spam bots from registering. also reports bots that are caught in the honeypot

= 0.5.3 =
* [+] added logging of user registration attempts for spam bots

= 0.5.2 =
* [*] adjusted the logic to check if block page was in place
* [+] added more quick access commands on the activity tab
* [+] initial support for cloudflare

= 0.5.1 =
* [+] added a pretty block page to inform users they are being blocked and the ability to report false positives
* [*] fixed several bugs in the update options function which was causing some installs to not work.
* [*] fixed more notices
* [*] fixed the automatic submission of uris, not currently used

= 0.5.0 =
* [+] added the ability to report 404 errors. in rapid succession, this could be a bot scanning for vulnerabilities
* [+] added the ability to report uri queries to analysis - not yet implemented
* [+] added a marketing notice to users using tinyshield longer than 30 days
* [*] added some additional checks to ensure validated data in certain cases

= 0.4.1 =
* [+] added a marketing optin on the registration form
* [*] added the functionality to not check traffic if the site is not activated with tinyshield. this will save our poor little servers from unintentional DDOS

= 0.4.0 =
* [!] notice - upon upgrading, your cached white and blocklists will clear themselves. permanent lists will be converted to the new format
* [+] added full support for ipv6 by switching the comparison method and storage of IP information both on the client and endpoints
* [*] fixed a bug that would cause a site to not function if the server is handing out corrupt data

= 0.3.5 =
* [+] added the ability to clear the permanent blocklist in rare cases, found under diagnostics on the settings tab

= 0.3.4 =
* [+] added detection of multisite and prevents from activating. support will come
* [+] added exclusive country block support (ie, block all but) - professional feature

= 0.3.3 =
* [+] added the ability to block countries based on country codes - professional feature
* [*] reworked the options save functionality to be more robust

= 0.3.2 =
* [+] added the ability to block tor exit nodes - professional feature
* [+] streamlined the premium subscription upgrade, will only show premium options to subscribers
* [*] limited who can see notifications from tinyShield
* [*] other minor bug fixes on endpoints

= 0.3.1 =
* [*] added permission checking on option updating
* [*] removed some old code

= 0.3.0 =
* [*] bug fixes with the permanent blocklist

= 0.2.9 =
* [+] added the navigation tabs as menu items
* [*] fixed a regression that would not block ips found in the local blocklist or remotely looked up *doh*

= 0.2.8 =
* [+] added support for reporting user enumeration - enabled by default

= 0.2.7 =
* [+] moved tinyShield to top level menu with icon (svg to come later)
* [*] fixed several php notices
* [*] moved geo_ip information for allowlist to paid subscription only due to cost

= 0.2.6 =
* [+] added a user defined permanent blocklist
* [*] changed the flow of the list checker to be more fluid

= 0.2.5 =
* [+] added the ability to disable tinyshield functionality without deactivating the plugin
* [*] changed the way the block functionality closes out to let other plugins use the functionality
* [*] moved options updating to admin_init to ensure we are always working with the latest option set
* [*] fixed some php notices
* [-] removed geo blocking until all countries can be added on an optional basis

= 0.2.4 =
* [+] added the ability to check outbound connections to compliment inbound. if outbound connections are found being blocked, it means your site is infected...
* [*] changed the expires column on the activity page to direction to identify outbound and inbound connections

= 0.2.3 =
* [+] changed the expiration date on perm allowlist to date added for clarity
* [+] will not check against any list if the user is logged in

= 0.2.2 =
* [+] added the ability to submit multiple ip addresses at one time to the perm allowlist
* [*] fixed an issue when removing and adding entries to the perm allowlist would cause an entry to be deleted
* [*] addressed a couple of notices and errors on activation [thanks vasyl martyniuk]

= 0.2.1 =
* [*] fixed an issue with options saving when updating plugin

= 0.2.0 =
* [+] added the feature to block top attacking countries
* [*] fixed a time expiration bug on the allowlist
* [*] fixed a time sorting issue

= 0.1.9 =
* [*] fixed a expiration bug where allowlist entries would be checked every 24 hours, it should be every hour
* [*] adjusted the author/website information

= 0.1.8 =
* [+] added the ability to clear locally cached lists in case of issues
* [+] added the ability to report a false positive from the activity log
* [+] added location information to allowlist
* [+] added the ability to register a site directly from the plugin
* [*] reworked the settings page to be more streamlined
* [*] fixed a potential fatal error if a wp_error is thrown on checking against endpoint
* [*] fixed some issues with timestamps not being correct on last access and expirations

= 0.1.7 =
* [+] added the ability to store the last time an IP address attempted to connect to the site
* [+] changed the "Allowed" and "Blocked" text to emojis to make things a little more visually pleasing
* [+] server side: moved crawler detection right after allowlist check to avoid crawlers being blocklisted
* [+] server side: added the addition of a new ip source list and also removed one that provided a lot of false positives

= 0.1.6 =
* [*] adjusted the allowlist expiration from 24 hours to 1 hour. If an attacker is blocklisted it will be caught much more quickly now.
* [*] fixed a few small bugs
* [+] added the ability to turn off reporting of failed logins
* [+] server side: added some additional sources for comment spam and web crawlers

= 0.1.5 =
* [*] fixed a display bug on the perm allowlist tab
* [*] fixed a date expiring bug when activating tinyshield for the first time

= 0.1.4 =
* [+] added the use of list tables for better visualization of the data
* [+] added the use of geoip data to show where blocklisted ip addresses are from
* [*] adjusted the data that is sent from the tinyshield servers to allow for expansion in the future
* [+] added the ability to manipulate the lists from the list tables (ie, move from one to another)
* [+] server side: added allowlists to prevent msnbots, googlebots, etc from being blocklisted by false positives
* plus more

= 0.1.3 =
* clarified site activation errors to not be so generic

= 0.1.2 =
* initial point release
