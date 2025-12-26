# Git Setup Guide

Follow these steps to push your project to GitHub:

## Step 1: Initialize Git Repository

```bash
cd vulnerability-scanner
git init
```

## Step 2: Add All Files

```bash
git add .
```

## Step 3: Create Initial Commit

```bash
git commit -m "Initial commit: Web Vulnerability Scanner"
```

## Step 4: Create GitHub Repository

1. Go to [GitHub](https://github.com) and sign in
2. Click the "+" icon in the top right
3. Select "New repository"
4. Name it: `vulnerability-scanner` (or your preferred name)
5. **DO NOT** initialize with README, .gitignore, or license (we already have these)
6. Click "Create repository"

## Step 5: Add Remote Repository

Replace `YOUR_USERNAME` with your GitHub username:

```bash
git remote add origin https://github.com/YOUR_USERNAME/vulnerability-scanner.git
```

Or if using SSH:
```bash
git remote add origin git@github.com:YOUR_USERNAME/vulnerability-scanner.git
```

## Step 6: Push to GitHub

```bash
git branch -M main
git push -u origin main
```

## Step 7: Add Screenshots

1. Save your screenshots in the `screenshots/` directory:
   - `dashboard.png`
   - `reports.png`
   - `charts.png`

2. Add and commit the screenshots:
```bash
git add screenshots/
git commit -m "Add application screenshots"
git push
```

## Future Updates

When you make changes:

```bash
git add .
git commit -m "Description of your changes"
git push
```

## Important Notes

- The `.env` file is already in `.gitignore` and won't be pushed (keeps your credentials safe)
- `node_modules/` is also ignored (too large for Git)
- Make sure to add your screenshots before pushing if you want them in the README

