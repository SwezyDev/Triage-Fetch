@echo off
cd ..
color 4
echo WARNING: This will permanently delete the entire reports/ folder.
echo All downloaded samples and report files will be lost.
echo.
pause

cls
color F

if exist reports (
    rmdir /s /q reports
    echo [[32m+[0m] Done. reports/ folder deleted.
) else (
    echo [[31m![0m] reports/ folder not found - already clean.
)

pause >nul