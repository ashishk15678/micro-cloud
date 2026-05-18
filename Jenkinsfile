pipeline {
  agent {
    docker {
      image 'ubuntu:24.04'
      args '-u root'
    }
  }

  stages {

    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Install dependencies') {
      steps {
        sh '''
          apt-get update

          DEBIAN_FRONTEND=noninteractive apt-get install -y \
            build-essential \
            meson \
            ninja-build \
            gcc \
            clang \
            pkg-config \
            git
        '''
      }
    }

    stage('Configure') {
      steps {
        sh '''
          rm -rf build
          meson setup build
        '''
      }
    }

    stage('Build') {
      steps {
        sh 'meson compile -C build'
      }
    }

    stage('Run tests') {
      steps {
        sh 'meson test -C build --print-errorlogs'
      }
    }

    stage('Sanitizer leak check') {
      steps {
        sh '''
          rm -rf build-sanitize

          meson setup build-sanitize \
            -Db_sanitize=address,undefined \
            --buildtype=debug

          meson compile -C build-sanitize

          ASAN_OPTIONS=detect_leaks=1:strict_string_checks=1:halt_on_error=1 \
            meson test -C build-sanitize --print-errorlogs

          client_bin="$(find build-sanitize -type f -executable -name client | head -n 1)"

          test -n "$client_bin"

          "$client_bin" > /dev/null
        '''
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'build/**,build-sanitize/**',
                       allowEmptyArchive: true
    }
  }
}