@echo off
cd ..
color 4
echo WARNING: This will permanently delete the entire seen_hashes.db file.
echo All cached hashes will be lost.
echo.
pause

cls
color F

if exist seen_hashes.db (
    del seen_hashes.db
    echo [[32m+[0m] Done. seen_hashes.db deleted.
) else (
    echo [[31m![0m] seen_hashes.db not found - already clean.
)

pause >nul