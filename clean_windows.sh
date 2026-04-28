#!/bin/bash
# Clean up the skill directory - remove compiled files and backups

cd /home/unlockerplus/.kilo/skills/shaby-tech-bug-hunter

echo "Cleaning up Windows-related artifacts..."

# Remove compiled binaries
rm -f mali_uaf_poc mali_uaf_poc.old

# Remove backup/error files
rm -f *.old 2>/dev/null
rm -f *-struct-error.c 2>/dev/null
rm -f *-headers-not-available.c 2>/dev/null
rm -f *-Copy.c 2>/dev/null

# Remove Zone.Identifier files (Windows ADS)
find . -name "*Zone.Identifier" -delete 2>/dev/null

# Remove any file with :Zone.Identifier in name
find . -name ":*" -delete 2>/dev/null

echo "Clean complete."
ls -la *.c *.md Makefile *.sh *.bat 2>/dev/null | grep -v "total"
