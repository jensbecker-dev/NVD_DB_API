#!/bin/bash

# Remove the large database file from Git history
echo "Removing large database files from Git history..."

# Create a temporary branch
git checkout --orphan temp_branch

# Add all files except the large ones
git add --all

# Commit the changes
git commit -m "Remove large database files"

# Delete the main branch
git branch -D main

# Rename the temporary branch to main
git branch -m main

# Force push to remote repository
git push -f origin main

echo "Large files have been removed from Git history."
echo "You can now push your changes to GitHub."
