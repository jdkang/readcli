#!/bin/bash

curl -s https://api.github.com/repos/iamadamdev/bypass-paywalls-chrome/releases/latest \
| grep "browser_download_url.*xpi" \
| cut -d : -f 2,3 \
| tr -d \" \
| wget -q -i - -O ./bypass-paywalls-firefox.xpi


