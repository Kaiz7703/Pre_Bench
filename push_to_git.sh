#!/bin/bash
# Push entire Benchmark_Q3 project to GitHub
# Repository: https://github.com/Kaiz7703/Pre_Bench.git

cd "d:/2026/Benchmark_Q3"

# Remove nested git repos (they were cloned from other repos)
rm -rf "./Prvention/PE/CVE-2026-20817/.git" 2>/dev/null
rm -rf "./Prvention/UACME/UACME/.git" 2>/dev/null

# Initialize git if needed
if [ ! -d ".git" ]; then
    git init
    git remote add origin https://github.com/Kaiz7703/Pre_Bench.git
    echo "Git initialized"
else
    echo "Git already initialized"
fi

# Stage all files
git add .

# Show what will be committed
echo ""
echo "=== Files to be committed ==="
git status --short | head -80

echo ""
echo "=== Ready to commit ==="
echo "Run the following commands manually:"
echo ""
echo "  git commit -m 'Initial commit: Benchmark Q3 - T1068 + T1548.002 EDR benchmark projects'"
echo "  git branch -M main"
echo "  git push -u origin main"
echo ""
echo "Or run: cd d:/2026/Benchmark_Q3 && git commit -m 'Initial commit' && git branch -M main && git push -u origin main"