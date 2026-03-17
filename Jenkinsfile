pipeline {
    agent any
    
    // Grabs the tools from your Mac's Homebrew path
    environment {
        PATH = "/opt/homebrew/bin:/usr/local/bin:${env.PATH}"
        GITHUB_TOKEN = credentials('github-token')
        REPO_OWNER = 'devsecops-poc-org-2026'
        REPO_NAME = 'service-c'
        // Forces Trivy to ignore Mac Docker settings so it can download its database
        DOCKER_CONFIG = '/tmp'
    }

    stages {
        stage('Initialize') {
            steps {
                script {
                    // Get the commit hash to update GitHub status
                    env.GIT_COMMIT = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
                }
            }
        }

        stage('Gitleaks Scan') {
            steps {
                // Run Gitleaks
                sh '''
                gitleaks detect -v --report-format json --report-path gitleaks-report.json || true
                
                # 1️⃣ Push Status to GitHub Commits
                curl -X POST -H "Authorization: Bearer $GITHUB_TOKEN" \
                -H "Accept: application/vnd.github.v3+json" \
                https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/statuses/$GIT_COMMIT \
                -d '{"state": "success", "context": "security/gitleaks", "description": "Scan Completed"}'
                '''
            }
        }

        stage('Trivy Scan & SARIF Upload') {
            steps {
                // Run Trivy and generate a SARIF report
                sh '''
                trivy fs . --format sarif --output trivy-results.sarif || true
                
                # 2️⃣ Upload SARIF to GitHub Security Tab
                if [ -f "trivy-results.sarif" ]; then
                    gzip -c trivy-results.sarif | base64 | tr -d '\n' > payload.b64
                    
                    echo '{"commit_sha":"'$GIT_COMMIT'","ref":"refs/heads/feature-security-test","sarif":"' > request.json
                    cat payload.b64 >> request.json
                    echo '"}' >> request.json
                    
                    curl -s -w "\\nHTTP_STATUS:%{http_code}\\n" -X POST \
                      -H "Authorization: Bearer $GITHUB_TOKEN" \
                      -H "Accept: application/vnd.github.v3+json" \
                      https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/code-scanning/sarifs \
                      -d @request.json
                else
                    echo "Trivy failed to generate SARIF."
                fi

                # Push Commit Status to GitHub
                curl -X POST -H "Authorization: Bearer $GITHUB_TOKEN" \
                https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/statuses/$GIT_COMMIT \
                -d '{"state": "success", "context": "security/trivy", "description": "Scan Completed"}'
                '''
            }
        }

        stage('PR Comment Summary') {
            steps {
                sh '''
                # Count the vulnerabilities found
                TRIVY_VULNS=$(grep -o '"ruleId":' trivy-results.sarif 2>/dev/null | wc -l | tr -d ' ' || echo "0")
                GITLEAKS_LEAKS=$(grep -o '"Description":' gitleaks-report.json 2>/dev/null | wc -l | tr -d ' ' || echo "0")

                # Safely find the PR Number for this exact commit
                PR_NUMBER=$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
                  -H "Accept: application/vnd.github.groot-preview+json" \
                  https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/commits/$GIT_COMMIT/pulls | \
                  python3 -c "import sys, json; data=json.load(sys.stdin); print(data[0]['number'] if isinstance(data, list) and len(data)>0 else '')")

                if [ -n "$PR_NUMBER" ]; then
                    echo "Found PR: $PR_NUMBER. Posting comment..."
                    
                    # Create the markdown comment payload
                    cat <<EOF > comment.json
{
  "body": "### 🛡️ DevSecOps Scan Summary\\n\\n**Gitleaks**\\n🔍 Secrets detected: $GITLEAKS_LEAKS\\n\\n**Trivy**\\n🚨 Vulnerabilities found: $TRIVY_VULNS\\n\\n*View full details in the GitHub Security tab.*"
}
EOF
                    
                    # Post comment to GitHub PR
                    curl -s -X POST -H "Authorization: Bearer $GITHUB_TOKEN" \
                      -H "Accept: application/vnd.github.v3+json" \
                      https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/issues/$PR_NUMBER/comments \
                      -d @comment.json
                else
                    echo "No active PR found for this commit. Did you open the PR in GitHub before running Jenkins?"
                fi
                '''
            }
        }
    }
}
