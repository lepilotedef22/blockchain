#!/bin/bash
osascript <<END
tell application "Terminal"
    do script "cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/NodeShell.py 1 --log debug"
end tell
END

osascript <<END
tell application "Terminal"
do script "cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/NodeShell.py 2 --log debug"
end tell
END

osascript <<END
tell application "Terminal"
do script "cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/NodeShell.py 3 --log debug"
end tell
END

osascript <<END
tell application "Terminal"
do script "cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/NodeShell.py 4 --log debug"
end tell
END

osascript <<END
tell application "Terminal"
do script "cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/NodeShell.py 5 --log debug"
end tell
END

osascript <<END
tell application "Terminal"
do script "cd /Users/denisverstraeten/Documents/Codes/Python/blockchain;python3 src/NodeShell.py 6 --log debug"
end tell
END
