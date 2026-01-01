package org.owasp.dependencycheck.gradle

import org.gradle.testkit.runner.GradleRunner
import spock.lang.Specification
import spock.lang.TempDir
import spock.util.io.FileSystemFixture

import static org.gradle.testkit.runner.TaskOutcome.SUCCESS

class DependencyCheckPluginIntegSpec extends Specification {

    @TempDir
    private FileSystemFixture fileSystemFixture

    def "Plugin can be added"() {
        given:
        fileSystemFixture.create {
            dir("app") {
                file("build.gradle").text = """
                        plugins {
                            id 'org.owasp.dependencycheck'
                        }
                    """.stripIndent()
            }
        }
        when:
        def result = GradleRunner.create()
                .withProjectDir(fileSystemFixture.resolve("app").toFile())
                .withArguments('tasks')
                .withPluginClasspath()
                .forwardOutput()
                .build()

        then:
        result.output.contains("$DependencyCheckPlugin.ANALYZE_TASK")
    }

    def "custom configurations are skipped when only scanning whitelisted configurations"() {
        given:
        fileSystemFixture.create {
            dir("custom") {
                file("build.gradle").text = """
                    plugins {
                        id 'org.owasp.dependencycheck'
                    }
                    apply plugin: 'java'

                    sourceCompatibility = 1.5
                    version = '1.0'

                    repositories {
                        mavenLocal()
                        mavenCentral()
                    }

                    dependencies {
                        implementation group: 'commons-collections', name: 'commons-collections', version: '3.2'
                    }
                    dependencyCheck {
                        analyzers.ossIndex.enabled = false
                        nvd.datafeedUrl = 'https://dependency-check.github.io/DependencyCheck/hb_nvd/'
                    }
                """.stripIndent()
            }
        }

        when:
        def result = GradleRunner.create()
                .withProjectDir(fileSystemFixture.resolve("custom").toFile())
                .withArguments(DependencyCheckPlugin.ANALYZE_TASK)
                .withPluginClasspath()
                .withDebug(true)
                .forwardOutput()
                .build()

        then:
        result.task(":$DependencyCheckPlugin.ANALYZE_TASK").outcome == SUCCESS
    }

    def "task completes successfully when configuration cache is enabled in Gradle 7.4"() {
        given:
        fileSystemFixture.create {
            dir("configCache") {
                file("build.gradle").text = """
                    plugins {
                        id 'org.owasp.dependencycheck'
                    }
                    apply plugin: 'java'

                    sourceCompatibility = 1.5
                    version = '1.0'

                    repositories {
                        mavenLocal()
                        mavenCentral()
                    }

                    dependencies {
                        implementation group: 'commons-collections', name: 'commons-collections', version: '3.2'
                    }
                    dependencyCheck {
                        analyzers.ossIndex.enabled = false
                        nvd.datafeedUrl = 'https://dependency-check.github.io/DependencyCheck/hb_nvd/'
                    }
                """.stripIndent()
            }
        }

        when:
        def result = GradleRunner.create()
                .withProjectDir(fileSystemFixture.resolve("configCache").toFile())
                .withArguments(DependencyCheckPlugin.ANALYZE_TASK, "--configuration-cache")
                .withPluginClasspath()
                .withDebug(true)
                .forwardOutput()
                .build()

        then:
        result.task(":$DependencyCheckPlugin.ANALYZE_TASK").outcome == SUCCESS
    }

    def "mulitple Analyze task configured"() {
        given:
        fileSystemFixture.create {
            dir("tasks") {
                file("build.gradle").text = """
                    plugins {
                        id 'org.owasp.dependencycheck'
                    }

                    dependencyCheck {
                        analyzers.ossIndex.enabled = false
                        nvd.datafeedUrl = 'https://dependency-check.github.io/DependencyCheck/hb_nvd/'
                        failBuildOnCVSS = 2.5
                        junitFailOnCVSS = 3.5
                    }

                    tasks.named('dependencyCheckAnalyze') {
                        config {
                            failBuildOnCVSS = 4.5
                            settings.put('junit.fail.on.cvss', 5.5)
                        }
                        doLast {
                            assert config.failBuildOnCVSS.get() == 4.5
                            assert settings.getFloat('junit.fail.on.cvss', 0) == 5.5
                            assert settings.getString('nvd.api.datafeed.url') == 'https://dependency-check.github.io/DependencyCheck/hb_nvd/'
                        }
                    }

                    tasks.register('testAnalyze', org.owasp.dependencycheck.gradle.tasks.Analyze) {
                        doLast {
                            assert config.failBuildOnCVSS.get() == 2.5
                            assert settings.getFloat('junit.fail.on.cvss', 0) == 3.5
                            assert settings.getString('nvd.api.datafeed.url') == 'https://dependency-check.github.io/DependencyCheck/hb_nvd/'
                        }
                    }

                    tasks.register('check') {
                        dependsOn tasks.withType(org.owasp.dependencycheck.gradle.tasks.Analyze)
                    }
                """.stripIndent()
            }
        }

        when:
        def result = GradleRunner.create()
                .withProjectDir(fileSystemFixture.resolve("tasks").toFile())
                .withArguments("check")
                .withPluginClasspath()
                .withDebug(true)
                .forwardOutput()
                .build()

        then:
        result.task(":$DependencyCheckPlugin.ANALYZE_TASK").outcome == SUCCESS
        result.task(":testAnalyze").outcome == SUCCESS
        result.task(":check").outcome == SUCCESS
    }
}
