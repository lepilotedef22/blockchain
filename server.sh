#!/bin/bash
osascript <<END
tell application "Terminal"
do script "workon bitcom;cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/Authenticate.py"
end tell
END
