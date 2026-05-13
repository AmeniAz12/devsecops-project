pipeline {
    agent any

    environment {
        IMAGE_NAME = "devsecops-image"
        IMAGE_TAG  = "${BUILD_NUMBER}"
    }

    options {
        timestamps()
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                sh '''
                rm -rf reports
                mkdir -p reports
                echo "WORKSPACE=$WORKSPACE"
                '''
            }
        }

        stage('SAST - Bandit') {
            steps {
                sh '''
                docker run --rm \
                  --volumes-from jenkins \
                  -w "$WORKSPACE" \
                  python:3.11-slim sh -c '
                    pip install --no-cache-dir bandit &&
                    mkdir -p reports &&
                    bandit -r app.py webapp.py osint_reporter/ \
                      --exclude ./.git,./backup-mini-app \
                      -f json \
                      -o reports/bandit-report.json || true
                  '

                ls -lh reports/bandit-report.json
                python3 scripts/fail_bandit.py
                '''
            }
        }

        stage('Secret Scan - Gitleaks') {
            steps {
                sh '''
                docker run --rm \
                  --volumes-from jenkins \
                  -w "$WORKSPACE" \
                  zricethezav/gitleaks:latest \
                  detect \
                  --source="$WORKSPACE" \
                  --no-git \
                  --report-format=json \
                  --report-path="$WORKSPACE/reports/gitleaks-report.json" || true

                test -f reports/gitleaks-report.json || echo "[]" > reports/gitleaks-report.json

                ls -lh reports/gitleaks-report.json
                python3 scripts/fail_gitleaks.py
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                sh '''
                docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .
                docker tag ${IMAGE_NAME}:${IMAGE_TAG} ${IMAGE_NAME}:latest
                docker images | grep ${IMAGE_NAME}
                '''
            }
        }

        stage('Image Scan - Trivy') {
            steps {
                sh '''
                docker run --rm \
                  -v /var/run/docker.sock:/var/run/docker.sock \
                  --volumes-from jenkins \
                  -w "$WORKSPACE" \
                  ghcr.io/aquasecurity/trivy:latest image \
                  --format json \
                  --output "$WORKSPACE/reports/trivy-report.json" \
                  --severity HIGH,CRITICAL \
                  ${IMAGE_NAME}:${IMAGE_TAG} || true

                ls -lh reports/trivy-report.json
                python3 scripts/fail_trivy.py
                '''
            }
        }

        stage('Deploy Local Staging For DAST') {
            steps {
                sh '''
                docker network create ci-net 2>/dev/null || true
                docker rm -f dast-app 2>/dev/null || true

                docker run -d \
                  --name dast-app \
                  --network ci-net \
                  ${IMAGE_NAME}:${IMAGE_TAG}

                sleep 8

                docker run --rm \
                  --network ci-net \
                  curlimages/curl:latest \
                  curl -fsS http://dast-app:5000/ | grep "SOC OSINT"
                '''
            }
        }

        stage('DAST - ZAP Baseline') {
            steps {
                sh '''
                docker run --rm \
                  --network ci-net \
                  --volumes-from jenkins \
                  -w "$WORKSPACE" \
                  --user root \
                  ghcr.io/zaproxy/zaproxy:stable \
                  zap-baseline.py \
                  -t http://dast-app:5000 \
                  -J reports/zap-report.json \
                  -r reports/zap-report.html || true

                ls -lh reports/zap-report.json reports/zap-report.html
                python3 scripts/fail_zap.py
                '''
            }
        }

        stage('Final Result') {
            steps {
                sh '''
                echo "Pipeline complete."
                echo "Image built: ${IMAGE_NAME}:${IMAGE_TAG}"
                echo "Latest tag: ${IMAGE_NAME}:latest"
                ls -lh reports
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/*', fingerprint: true, allowEmptyArchive: true
            sh '''
            docker rm -f dast-app 2>/dev/null || true
            '''
        }

        success {
            echo 'Pipeline passed all security gates.'
        }

        failure {
            echo 'Pipeline blocked by security gates or failed during execution.'
        }
    }
}
