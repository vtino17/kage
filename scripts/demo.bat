@echo off
echo === KAGE Demo ===
echo.
echo 1. Create a vulnerable test file
echo --^> printf "const apiKey = 'sk-1234567890abcdef';\nconst dbPass = 'password123';const sql = 'SELECT * FROM users WHERE id = ' + userId;" > demo-test.js
echo.
echo 2. Run KAGE scan
echo --^> kage scan .
echo.
echo 3. Run KAGE scan with AI analysis (requires AI engine running)
echo --^> kage scan . --ai
echo.
echo 4. Scan a GitHub repo
echo --^> kage scan github.com/expressjs/express
echo.
echo 5. Generate HTML report
echo --^> kage scan . --format html ^> report.html
echo.
echo Done.
