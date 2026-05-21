#!/bin/bash

cd ..

echo -e "\033[34m"
echo "WARNING: This will permanently delete the entire reports/ folder."
echo "All downloaded samples and report files will be lost."
echo ""
read -p "Press Enter to continue or Ctrl+C to cancel..."

clear
echo -e "\033[37m"

if [ -d "reports" ]; then
    rm -rf reports
    echo -e "[\033[32m+\033[0m] Done. reports/ folder deleted."
else
    echo -e "[\033[31m!\033[0m] reports/ folder not found - already clean."
fi

read -p "Press Enter to exit..."