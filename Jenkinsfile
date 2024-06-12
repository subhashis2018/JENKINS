#!groovy

library 'reference-pipeline'

library 'AppServiceAccount'

library 'fxg-reference-pipeline'

library 'CICD-FOSS-V2'

 

pipeline {

    parameters {

        string(name: "BRANCH_NAME", defaultValue: "release", description: "Full name of the branch to build.")

        booleanParam(name: "FORTIFY_ANALYSIS", defaultValue: false, description: "Perform a Fortify security scan on this project.")

    }

 

    agent {

        node {

            label 'Docker-c0035875'

        }

    }

 

    options {

        buildDiscarder(logRotator(numToKeepStr: '10'))

    }

 

    tools {

        jdk 'JAVA_17'

    }

 

    environment {

                              APPLICATION_PACKAGE = "eai3540420.com.fdxfe.cpudwv"

                              APP_NAME = 'fdxfe-exop-cpudwv-rpo-core-collector'

                              APP_VERSION = "$version"

                              APP_PAM_ID = '64847002'

                              CF_ORG = '3540420'

                              GROUP_ID = 'com.fdxfe.cpudwv'

 

                              NEXUS_CREDS_ID = '3540420_nexus'

                              NEXUS_URL_UPLOAD = 'nexus.prod.cloud.com:8443/nexus'

                              NEXUS_REPO_NAME = 'snapshot'

 

                              MICROSOFT_TEAMS_WEBHOOK = 'https://my.webhook.office.com/webhookb2/97c46ce1-8c09-45f6-9809-94bf27165cf5@b945c813-dce6-41f8-8457-5a12c2fe15bf/IncomingWebhook/6ba7f5b94d2241f8b9cbc531acfdaa10/ed00cbcb-d4ed-429d-9d6a-3e97ade4a307'

                              CPUDWV_ACTUATOR = credentials('CPUDWV-Actuator')

                              ACTUATOR_USERNAME = "${CPUDWV_ACTUATOR_USR}"

                              ACTUATOR_PASSWORD = "${CPUDWV_ACTUATOR_PSW}"

                              CPUDWV_JMS_CREDENTIALS = credentials('CPUDWV_JMS_CREDENTIALS_NON_PRD')

                              CPUDWV_CASSANDRA_CREDENTIALS = credentials('CPUDWV_CASSANDRA_CREDENTIALS_L2')

                              CF_APPDSPACE= "RELEASE"

                              CURR_CF_API = ""

                              CURR_SPACE = ""

        GRADLE_OPTS="-Dgradle.user.home=/opt/jenkins/.gradle -Dhttp.proxyHost=internet.proxy.com -Dhttp.proxyPort=3128"

    }

 

    stages {

        stage("Checkout") {

            steps {

                cleanWs()

                echo 'Workspace cleaned'

 

                script {

                    script {

                        echo 'GithubTargetBranch: ' + params.BRANCH_NAME

                        SOURCE_BRANCH = params.BRANCH_NAME.trim()

                    }

                }

                echo 'Start check out from: ' + "${SOURCE_BRANCH}"

                git url: url, branch: "${SOURCE_BRANCH}", credentialsId: '3540420_RPO-Core-Collector_Deploy_Key'

                echo 'Stage checkout - Complete'

            }

        }

 

        stage("Build") {

            steps {

                sh 'chmod +x gradlew'

                script {

                    GIT_COMMIT_HASH = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()

                    GIT_COMMIT_HASH = "${GIT_COMMIT_HASH}-SNAPSHOT"

                    APP_VERSION = sh(script: "./gradlew -P revision=$GIT_COMMIT_HASH properties -q | grep \"version:\" | awk '{print \$2}'", returnStdout: true).trim()

                    APP_NAME = sh(script: "./gradlew -P revision=$GIT_COMMIT_HASH properties -q | grep \"name:\" | awk '{print \$2}'", returnStdout: true).trim()

                    echo APP_NAME

                    echo APP_VERSION

                }

 

                sh "./gradlew -P revision=$GIT_COMMIT_HASH clean build"

                sh "ls -l build/libs"

                echo "Jar : ${APP_NAME}-${APP_VERSION}"

            }

            post {

                always {

                    codeQuality junitPath: '**/test-results/test/*.xml', pmdPath: '**/pmd/*.xml', findBugsPath: '**/spotbugs/*.xml'

                }

                success {

                    echo 'Build complete'

                    stash includes: "**/libs/$APP_NAME-$APP_VERSION" + ".jar", name: "builtArtifact"

                    stash includes: '**/jacoco/*.exec', name: 'jacocoTestCoverage'

                    stash includes: '**/', name: 'buildDir'

                    stash includes: '**/test-results/test/*.xml', name: 'unitTestResults'

                }

            }

        }

 

        stage("Static Code Analysis") {

            steps {

                parallel(

                        jacoco: {

                            unstash 'jacocoTestCoverage'

                            unstash 'buildDir'

                             jacoco exclusionPattern: '**/model/**, **/*Test*.class, **/jaxb/**, **/entity/**, **/config/**, **/FdxfeExopCpudwvRpoCoreDataCollectorApplication*',

                             execPattern: '**build/jacoco/test.exec'

                        },

                        junit: {

                            unstash 'unitTestResults'

                            junit healthScaleFactor: 0.1, testResults: '**/test-results/test/*.xml'

                        }

                )

            }

        }

        stage('FOSS - Scan, Save and Submit Nexus IQ Report') {

            tools {

                jdk 'JAVA_8'

            }

            steps {

                withCredentials([[ $class: 'UsernamePasswordMultiBinding', credentialsId: '3540420_FOSS_SERVICE_ACCOUNT', usernameVariable: 'SERVICE_ACCOUNT_USER', passwordVariable: 'SERVICE_ACCOUNT_PASSWORD' ]]) {

                    script {

                        def nexusEval = runNexusPolicyEvaluation iqTarget: "build/",

                                svcUser: "${SERVICE_ACCOUNT_USER}",

                                svcPwd: "${SERVICE_ACCOUNT_PASSWORD}"

 

                        saveNexusPolicyEvaluation applicationVersion: APP_VERSION,

                                zone: 'Internal Usage - Back Office (Includes COPE mobile Devices, Desktop Development, Testing, support and maintenance)',

                                iqRptId: nexusEval.get("iqRptId"),

                                svcUser: "${SERVICE_ACCOUNT_USER}",

                                svcPwd: "${SERVICE_ACCOUNT_PASSWORD}"

 

                        submitFossRequestForNexusPolicyEvaluation applicationVersion: APP_VERSION,

                                svcUser: "${SERVICE_ACCOUNT_USER}",

                                svcPwd: "${SERVICE_ACCOUNT_PASSWORD}"

                    }

                }

            }

        }

 

        stage("Fortify") {

               when {

                              expression {

                                             params.FORTIFY_ANALYSIS == true

                              }

               }

 

               steps {

                              echo 'Stashing source for fortify'

                              stash includes: '**', name: 'source'

                              echo 'Get fortify scripts'

                              getFortifyScripts()

                              echo 'Running fortify analysis'

                              startFortifyAnalysis("${CF_ORG}_${APP_NAME}")

               }

        }

 

        stage('Nexus Upload') {

            environment {

                NEXUS_GROUP_ID = "eai${CF_ORG}.${GROUP_ID}"

            }

            steps {

                unstash 'builtArtifact'

                nexusArtifactUploader nexusUrl: "${NEXUS_URL_UPLOAD}",

                        credentialsId: "${NEXUS_CREDS_ID}",

                        repository: "${NEXUS_REPO_NAME}",

                        nexusVersion: 'nexus3',

                        protocol: 'https',

                        groupId: "${env.NEXUS_GROUP_ID}",

                        version: "${APP_VERSION}",

                        artifacts: [[

                                            artifactId: "${APP_NAME}",

                                            classifier: '',

                                            file      : "build/libs/${APP_NAME}-${APP_VERSION}.jar",

                                            type      : 'jar'

                                    ]]

            }

        }

 

        stage("Deploy in Release") {

 

            environment {

                CF_SPACE = "release"

                CF_ORG = "3540420"

                CURR_SPACE = "${CF_SPACE}"

            }

 

            stages{

                // Start of CLW stage

 

                stage('Deploy to CLW')

                        {  // Start of Deploy to CLW stage

 

                            stages{

                                // Start of CLW stages

 

                                // create service and deploy - CLWDEV4

                                stage("CreateService And Deploy to release space clwdev4-az1")

                                        {

 

                                            environment {

                                                PCF_FOUNDATION = "clwdev4-az1"

                                                CF_API =

                                                CF_FOUNDATION = "${PCF_FOUNDATION}"

                                                CURR_CF_API = "${CF_API}"

                                                CURR_PROFILE= "releaseCLW"

                                                INSTANCES_COUNT="1"

                                            }

                                            steps {

                                                setupServicesAndDeployIntoFoundation()

                                            }

                                        }

 

                                stage("CreateService And Deploy to release space clwdev4-az2")

                                        {

 

                                            environment {

                                                PCF_FOUNDATION = "clwdev4-az2"

                                                CF_API =

                                                CF_FOUNDATION = "${PCF_FOUNDATION}"

                                                CURR_CF_API = "${CF_API}"

                                                CURR_PROFILE= "releaseCLW"

                                                INSTANCES_COUNT="1"

                                            }

                                            steps {

                                                setupServicesAndDeployIntoFoundation()

                                            }

                                        }

 

                                stage("CreateService And Deploy to release space clwdev4-az3")

                                        {

 

                                            environment {

                                                PCF_FOUNDATION = "clwdev4-az3"

                                                CF_API

                                                CF_FOUNDATION = "${PCF_FOUNDATION}"

                                                CURR_CF_API = "${CF_API}"

                                                CURR_PROFILE= "releaseCLW"

                                                INSTANCES_COUNT="1"

                                            }

                                            steps {

                                                setupServicesAndDeployIntoFoundation()

                                            }

                                        }

 

                            } // end of CLW stages

 

                        } // End of Deploy to CLW stage

 

            } // End of CLW stage

 

        }

    }

 

    post {

        always {

            cleanWs()

            always{

                junit allowEmptyResults: true, testResults: '**/build/test-results/test/**/*.xml'

                dry canComputeNew: false, defaultEncoding: '', healthy: '', pattern: '', unHealthy: ''

                zip archive: true, dir: 'build/test-results/test/', glob: '', zipFile: 'build/test-results/test.zip'

            }

        }

        success {

            script {

                office365ConnectorSend message: "<b>${APP_NAME}</b> ${APP_VERSION} build successful.",

                        status: "Success",

                        color: "#32CD32",

                        webhookUrl: MICROSOFT_TEAMS_WEBHOOK

            }

        }

        failure {

            script {

                office365ConnectorSend message: "<b>${APP_NAME}</b> ${APP_VERSION} build failure.",

                        status: "Failure",

                        color: "#FF0000",

                        webhookUrl: MICROSOFT_TEAMS_WEBHOOK

            }

        }

    }

}

 

//CLW Deployment methods

void setupServicesAndDeployIntoFoundation()

{ // Start of deployInto_specificFoundation

 

 

    executeServicesSetupForEachFoundation()

    executeDeploymentIntoEachFoundation()

 

 

} // End of deployInto_CLWDEV1

 

 

void executeServicesSetupForEachFoundation()

{

 

    echo "\u2705 \u2705 \u2705 Create Services \u2705 \u2705 \u2705"

    println 'Configuring User Provided Services'

    pcfDeploy pamId: APP_PAM_ID,

            url: CF_API,

            space: CF_SPACE,

            cfcmd: 'version'

 

    sh '''#!/bin/sh

                                                            chmod +x cf

                                                            export PATH=${PATH}:${WORKSPACE}

                currentServices=$(cf services)

                                                 echo ${currentServices}

 

                                                 cf service appd || cf create-service appdynamics aa-test appd

                cf service autoscaler || cf create-service app-autoscaler standard autoscaler

 

                cf uups dynamic-profile -p '{"DYNAMIC_PROFILE":"'${CURR_PROFILE}'"}' ||

                cf cups dynamic-profile -p '{"DYNAMIC_PROFILE":"'${CURR_PROFILE}'"}'

 

                cf uups fdxfe-exop-cpudwv-actuator -p '{"ACTUATOR_USERNAME":"'${CPUDWV_ACTUATOR_USR}'","ACTUATOR_PASSWORD":"'${CPUDWV_ACTUATOR_PSW}'"}' ||

                cf cups fdxfe-exop-cpudwv-actuator -p '{"ACTUATOR_USERNAME":"'${CPUDWV_ACTUATOR_USR}'","ACTUATOR_PASSWORD":"'${CPUDWV_ACTUATOR_PSW}'"}'

 

                cf uups fdxfe-exop-cpudwv-jms -p '{"CPUDWV_JMS_USERNAME":"'${CPUDWV_JMS_CREDENTIALS_USR}'","CPUDWV_JMS_PASSWORD":"'${CPUDWV_JMS_CREDENTIALS_PSW}'"}' ||

                cf cups fdxfe-exop-cpudwv-jms -p '{"CPUDWV_JMS_USERNAME":"'${CPUDWV_JMS_CREDENTIALS_USR}'","CPUDWV_JMS_PASSWORD":"'${CPUDWV_JMS_CREDENTIALS_PSW}'"}'

 

                cf uups fdxfe-exop-cpudwv-cassandra -p '{"CPUDWV_CASSANDRA_USERNAME":"'${CPUDWV_CASSANDRA_CREDENTIALS_USR}'","CPUDWV_CASSANDRA_PASSWORD":"'${CPUDWV_CASSANDRA_CREDENTIALS_PSW}'"}' ||

                cf cups fdxfe-exop-cpudwv-cassandra -p '{"CPUDWV_CASSANDRA_USERNAME":"'${CPUDWV_CASSANDRA_CREDENTIALS_USR}'","CPUDWV_CASSANDRA_PASSWORD":"'${CPUDWV_CASSANDRA_CREDENTIALS_PSW}'"}'

 

                                                            echo ${currentServices}

                                                            '''

 

} //End of executeServicesSetupForEachFoundation() method

 

 

 

void executeDeploymentIntoEachFoundation(){

 

    echo "\u2705 \u2705 \u2705 Deploy Services \u2705 \u2705 \u2705"

    // Use the pcfDeploy to Authenticate and get version

    pcfDeploy(

            pamId: APP_PAM_ID,

            url: CF_API,

            space: CF_SPACE,

            cfcmd: '--version'

    )

 

    // Push the application to pcf

    sh """

                              export PATH=${PATH}:${WORKSPACE}

                              cf push ${APP_NAME} -f manifest.yml  \

                      --var space="${CF_SPACE}" \

                      --var appDspace="${CF_APPDSPACE}" \

                      --var foundation="${CF_FOUNDATION}" \

           --var profile="${CURR_PROFILE}" \

                      --var version="${APP_VERSION}" \

                      --var instance="${INSTANCES_COUNT}"

 

                              cf set-env ${APP_NAME} "nexusVersion" "${APP_VERSION}"

                              """

 

}