pipeline {
  agent any

  environment {
    IMAGE = "ghcr.io/ameniaz12/devsecops-project"
    CREDS = "github-creds"
  }

  stages {
    stage('Checkout') {
      steps { checkout scm }
    }

    stage('Build & Tag') {
      steps {
        script {
          def tag = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
          env.TAG = tag
          sh "docker build -t ${IMAGE}:${TAG} ."
        }
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
      steps { sh "docker push ${IMAGE}:${TAG}" }
    }
  }

  post {
    always { sh "docker logout ghcr.io || true" }
  }
}
