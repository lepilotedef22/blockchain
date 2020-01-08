#!/bin/bash
osascript <<END
tell application "Terminal"
do script "workon bitcom;cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/NodeShell.py 1"
end tell
END

osascript <<END
tell application "Terminal"
do script "workon bitcom;cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/NodeShell.py 2"
end tell
END

osascript <<END
tell application "Terminal"
do script "workon bitcom;cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/NodeShell.py 3"
end tell
END

osascript <<END
tell application "Terminal"
do script "workon bitcom;cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/NodeShell.py 4"
end tell
END

osascript <<END
tell application "Terminal"
do script "workon bitcom;cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/NodeShell.py 5"
end tell
END

osascript <<END
tell application "Terminal"
do script "workon bitcom;cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/NodeShell.py 6"
end tell
END
