#!/bin/bash
osascript <<END
tell application "Terminal"
do script "cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/Authenticate.py"
end tell
END
