@echo off
echo Terminating orphaned Chromium / Playwright processes...
taskkill /F /IM chrome.exe /T 2>nul
taskkill /F /IM chromedriver.exe /T 2>nul
echo Done. Zombie browser processes cleaned up.
