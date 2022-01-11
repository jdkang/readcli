# readcli
Tool to help scrape, mirror, and push content s3 website, and then queue in Pocket.

The 'mirror site' also includes a `.png` screenshot and `.pdf` "print to PDF" version.

Uses Selenium, Newspaper3k, S3 Websites, and Pocket API.

Additional ability to consume links via Slack Bot or Google Tasks API (see `settings.cfg.example`)

# deps
Probably doesn't work on windows without a few tweaks to pathing.

- Python 3.9
- [poetry](https://python-poetry.org/)
- firefox (tested on `89.0.1`)
- geckodriver (tested on `0.30.0`)
- firefox dependecies (varies by system). Example for Debian 11:
    - libgtk-3-0
    - gconf-service
    - libasound2
    - libatk1.0-0
    - libc6
    - libcairo2
    - libcups2
    - libdbus-1-3
    - libexpat1
    - libfontconfig1 
    - libgcc1
    - libgconf-2-4
    - libgdk-pixbuf2.0-0
    - libglib2.0-0
    - libgtk-3-0
    - libnspr4
    - libpango-1.0-0
    - libpangocairo-1.0-0
    - libstdc++6
    - libx11-6
    - libx11-xcb1
    - libxcb1
    - libxcomposite1
    - libxcursor1
    - libxdamage1
    - libxext6
    - libxfixes3
    - libxi6
    - libxrandr2
    - libxrender1
    - libxss1
    - libxtst6
    - ca-certificates
    - fonts-liberation
    - libnss3
    - lsb-release
    - xdg-utils
    - wget

## useful links
- [geckodriver Supported platforms¶](https://firefox-source-docs.mozilla.org/testing/geckodriver/Support.html)
- [Firefox Releases](https://archive.mozilla.org/pub/firefox/releases/) - e.g. `https://archive.mozilla.org/pub/firefox/releases/{{ firefox_version }}/linux-x86_64/en-US/firefox-{{ firefox_version }}.tar.bz2`
- [geckodriver Releases](https://github.com/mozilla/geckodriver/releases) - e.g. `https://github.com/mozilla/geckodriver/releases/download/v{{ geckodriver_version }}/geckodriver-v{{ geckodriver_version }}-linux64.tar.gz`

## binaries
folder          | description
----------------|-----------------------------------------
`xpi/`          | firefox plugins that get loaded into selenium, e.g. [bypass-paywall-chrome](https://github.com/iamadamdev/bypass-paywalls-chrome)
`bin/`          | **EXPECTS**; `geckodriver` and [compatible](https://firefox-source-docs.mozilla.org/testing/geckodriver/Support.html) `firefox/firefox` binary

# setup
## restore deps
`poetry install`

## pocket
1. Obtain a [pocket consumer key](https://getpocket.com/developer/docs/authentication)
2. update `pocket_consumer_key` in `settings.cfg`
3. user `./readcli pocket gen-access-token` to get an **access token**
4. update `pocket_access_token` in `settings.cfg` 

## aws
1. setup an s3 bucket website (e.g. [with domain name](https://docs.aws.amazon.com/AmazonS3/latest/userguide/website-hosting-custom-domain-walkthrough.html))
2. create IAM user with s3 bucket permissions
3. update in `settings.cfg`
    - `bucket_name`
    - `bucket_is_domain_alias`
    - `aws_access_key_id`
    - `aws_secret_access_key`

## slack
1. setup a [slack bot](https://slack.dev/bolt-python/tutorial/getting-started)
2. update in `settings.cfg`
    - `bot_token`
    - `app_token`