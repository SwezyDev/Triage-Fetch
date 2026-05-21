#!/bin/bash

cd ..

echo -e "\033[34m"
echo "WARNING: This will permanently delete the entire seen_hashes.db file."
echo "All cached hashes will be lost."
echo ""
read -p "Press Enter to continue or Ctrl+C to cancel..."

clear
echo -e "\033[37m"

if [ -f "seen_hashes.db" ]; then
    rm seen_hashes.db
    echo -e "[\033[32m+\033[0m] Done. seen_hashes.db file deleted."
else
    echo -e "[\033[31m!\033[0m] seen_hashes.db file not found - already clean."
fi

read -p "Press Enter to exit..."