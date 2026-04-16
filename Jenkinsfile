pipeline {
    agent any

    environment {
        IMAGE = "ghcr.io/ameniaz12/devsecops-project"
        CREDS = "github-creds"
    }

    options {
        timestamps()
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'mkdir -p reports'
            }
        }

        stage('Prepare Tag') {
            steps {
                script {
                    def tag = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
                    env.TAG = tag
                }
            }
        }

        stage('SAST - Bandit') {
            steps {
                sh '''
                docker run --rm -v "$PWD:/src" -w /src python:3.11-slim sh -c "
                pip install --no-cache-dir bandit &&
                bandit -r . -f json -o reports/bandit-report.json
                "
                python3 scripts/fail_bandit.py
                '''
            }
        }

        stage('Secret Scan - Gitleaks') {
            steps {
                sh '''
                docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest \
                detect --source=/repo --report-format=json --report-path=/repo/reports/gitleaks-report.json

                python3 scripts/fail_gitleaks.py
                '''
            }
        }

        stage('Build & Tag') {
            steps {
                sh '''
                docker build -t ${IMAGE}:${TAG} .
                docker tag ${IMAGE}:${TAG} ${IMAGE}:latest
                '''
            }
        }

        stage('Image Scan - Trivy') {
            steps {
                sh '''
                docker run --rm \
                  -v /var/run/docker.sock:/var/run/docker.sock \
                  -v "$PWD:/work" \
                  ghcr.io/aquasecurity/trivy:latest image \
                  --format json \
                  --output /work/reports/trivy-report.json \
                  --severity HIGH,CRITICAL \
                  ${IMAGE}:${TAG}

                python3 scripts/fail_trivy.py
                '''
            }
        }

        stage('Deploy Local Staging For DAST') {
            steps {
                sh '''
                docker network inspect ci-net >/dev/null 2>&1 || docker network create ci-net
                docker rm -f dast-app >/dev/null 2>&1 || true

                docker run -d \
                  --name dast-app \
                  --network ci-net \
                  ${IMAGE}:${TAG}

                sleep 8

                docker run --rm \
                  --network ci-net \
                  curlimages/curl:latest \
                  curl -fsS http://dast-app:5000/
                '''
            }
        }

        stage('DAST - ZAP Baseline') {
            steps {
                sh '''
                docker run --rm \
                  --network ci-net \
                  -v "$PWD/reports:/zap/wrk" \
                  ghcr.io/zaproxy/zaproxy:stable \
                  zap-baseline.py \
                  -t http://dast-app:5000 \
                  -J zap-report.json \
                  -r zap-report.html || true

                python3 scripts/fail_zap.py
                '''
            }
        }

        stage('Login GHCR') {
            steps {
                withCredentials([usernamePassword(credentialsId: "${CREDS}", usernameVariable: 'U', passwordVariable: 'P')]) {
                    sh 'echo "$P" | docker login ghcr.io -u "$U" --password-stdin'
                }
            }
        }

        stage('Push Image') {
            steps {
                sh '''
                docker push ${IMAGE}:${TAG}
                docker push ${IMAGE}:latest
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/*', fingerprint: true
            sh '''
            docker rm -f dast-app >/dev/null 2>&1 || true
            docker logout ghcr.io || true
            '''
        }
        success {
            echo 'Pipeline passed all security gates and pushed image successfully.'
        }
        failure {
            echo 'Pipeline blocked by security gates or failed during execution.'
        }
    }
}
