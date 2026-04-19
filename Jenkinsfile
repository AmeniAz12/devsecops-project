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
                sh 'mkdir -p reports'
            }
        }

        stage('Secret Scan - Gitleaks') {
            steps {
                sh '''
                docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest \
                  detect --source=/repo \
                  --report-format=json \
                  --report-path=/repo/reports/gitleaks-report.json || true
                python3 scripts/fail_gitleaks.py
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                sh '''
                docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .
                docker tag ${IMAGE_NAME}:${IMAGE_TAG} ${IMAGE_NAME}:latest
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
                  ${IMAGE_NAME}:${IMAGE_TAG} || true
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
                sleep 5
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

        stage('Push Image') {
            when {
                expression {
                    currentBuild.currentResult == null ||
                    currentBuild.currentResult == 'SUCCESS'
                }
            }
            steps {
                sh '''
                echo "Add GHCR login/tag/push here"
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/*', fingerprint: true
            sh '''
            docker rm -f dast-app 2>/dev/null || true
            '''
        }
        success {
            echo 'Pipeline passed all security gates.'
        }
        failure {
            echo 'Pipeline blocked by security gates.'
        }
    }
}
