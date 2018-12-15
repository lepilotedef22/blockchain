#!/bin/bash
osascript <<END
tell application "Terminal"
    do script "cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/Node.py 1"
end tell
END

osascript <<END
tell application "Terminal"
do script "cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/Node.py 2"
end tell
END

osascript <<END
tell application "Terminal"
do script "cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/Node.py 3"
end tell
END

osascript <<END
tell application "Terminal"
do script "cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/Node.py 4"
end tell
END

osascript <<END
tell application "Terminal"
do script "cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/Node.py 5"
end tell
END

osascript <<END
tell application "Terminal"
do script "cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/Node.py 6"
end tell
END
