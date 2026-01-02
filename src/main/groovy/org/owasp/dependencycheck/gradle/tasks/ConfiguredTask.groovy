/*
 * This file is part of dependency-check-gradle.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */

package org.owasp.dependencycheck.gradle.tasks

import org.gradle.api.DefaultTask
import org.gradle.api.InvalidUserDataException
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Nested
import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import org.owasp.dependencycheck.gradle.extension.DependencyCheckTaskConfig
import org.owasp.dependencycheck.gradle.service.SlackNotificationSenderService
import org.owasp.dependencycheck.utils.Downloader
import org.owasp.dependencycheck.utils.Settings

import static org.owasp.dependencycheck.utils.Settings.KEYS.*

/**
 * Standard class to read in the configuration and populated the ODC settings.
 *
 * @author Jeremy Long
 */
@groovy.transform.CompileStatic
abstract class ConfiguredTask extends DefaultTask {

    private final DependencyCheckTaskConfig config
    @Internal
    final DependencyCheckExtension extension = (DependencyCheckExtension) project.extensions.findByName('dependencyCheck')
    @Internal
    Settings settings
    @Internal
    String PROPERTIES_FILE = 'task.properties'

    ConfiguredTask() {
        this(DependencyCheckTaskConfig)
    }

    ConfiguredTask(Class<? extends DependencyCheckTaskConfig> configType) {
        this.config = project.objects.newInstance(configType)
        this.config.failOnError.set(extension.failOnError)
        this.config.settings.value(settingsMap(extension))
    }

    @Nested
    DependencyCheckTaskConfig getConfig() {
        config
    }

    /**
     * Initializes the settings object. If the setting is not set the
     * default from dependency-check-core is used.
     */
    protected void initializeSettings() {
        settings = new Settings()

        InputStream taskProperties = null
        try {
            taskProperties = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE)
            settings.mergeProperties(taskProperties)
        } catch (IOException ex) {
            logger.warn('Unable to load the dependency-check gradle task.properties file.')
            logger.debug('', ex)
        } finally {
            if (taskProperties != null) {
                try {
                    taskProperties.close()
                } catch (IOException ex) {
                    logger.debug("", ex)
                }
            }
        }

        for (def e : this.config.settings.get().entrySet()) {
            switch (e.value) {
            case Boolean:
                settings.setBoolean(e.key, (Boolean) e.value)
                break
            case String:
                settings.setString(e.key, (String) e.value)
                break
            case Float:
            case Double:
            case BigDecimal:
                settings.setFloat(e.key, e.value as Float)
                break
            case Number:
                settings.setInt(e.key, Math.toIntExact(e.value as Long))
                break
            case String[]:
            case Collection:
                settings.setArrayIfNotEmpty(e.key, e.value as String[])
                break
            default:
                throw new IllegalArgumentException("Key $e.key has unsupported value type: $e.value")
            }
        }

        Downloader.getInstance().configure(settings);
    }

    private Map<String, Object> settingsMap(DependencyCheckExtension config) {
        Map<String, Object> settings = [:]

        settings.put(AUTO_UPDATE, config.autoUpdate.getOrNull())

        String[] suppressionLists = determineSuppressions(config.suppressionFiles.getOrElse([]), config.suppressionFile.getOrNull())

        settings.put(SUPPRESSION_FILE, suppressionLists)
        settings.put(SUPPRESSION_FILE_USER, config.suppressionFileUser.getOrNull() ?: null)
        settings.put(SUPPRESSION_FILE_PASSWORD, config.suppressionFilePassword.getOrNull() ?: null)
        settings.put(SUPPRESSION_FILE_BEARER_TOKEN, config.suppressionFileBearerToken.getOrNull() ?: null)
        settings.put(HINTS_FILE, config.hintsFile.getOrNull() ?: null)

        configureProxy(settings, config)

        configureSlack(settings, config)

        //settings.put(CONNECTION_TIMEOUT, connectionTimeout)
        settings.put(DATA_DIRECTORY, config.data.directory.getOrNull())
        settings.put(DB_DRIVER_NAME, config.data.driver.getOrNull() ?: null)
        settings.put(DB_DRIVER_PATH, config.data.driverPath.getOrNull() ?: null)
        settings.put(DB_CONNECTION_STRING, config.data.connectionString.getOrNull() ?: null)
        settings.put(DB_USER, config.data.username.getOrNull() ?: null)
        settings.put(DB_PASSWORD, config.data.password.getOrNull() ?: null)


        settings.put(NVD_API_KEY, config.nvd.apiKey.getOrNull() ?: null)
        settings.put(NVD_API_ENDPOINT, config.nvd.endpoint.getOrNull() ?: null)
        settings.put(NVD_API_DELAY, config.nvd.delay.getOrNull())
        settings.put(NVD_API_RESULTS_PER_PAGE, config.nvd.resultsPerPage.getOrNull())
        settings.put(NVD_API_MAX_RETRY_COUNT, config.nvd.maxRetryCount.getOrNull())
        settings.put(NVD_API_VALID_FOR_HOURS, config.nvd.validForHours.getOrNull());

        settings.put(NVD_API_DATAFEED_URL, config.nvd.datafeedUrl.getOrNull() ?: null)
        if (config.nvd.datafeedUser.getOrNull() && config.nvd.datafeedPassword.getOrNull()) {
            settings.put(NVD_API_DATAFEED_USER, config.nvd.datafeedUser.getOrNull() ?: null)
            settings.put(NVD_API_DATAFEED_PASSWORD, config.nvd.datafeedPassword.getOrNull() ?: null)
        }
        settings.put(NVD_API_DATAFEED_BEARER_TOKEN, config.nvd.datafeedBearerToken.getOrNull() ?: null)
        settings.put(NVD_API_DATAFEED_START_YEAR, config.nvd.datafeedStartYear.getOrNull())

        settings.put(DOWNLOADER_QUICK_QUERY_TIMESTAMP, config.quickQueryTimestamp.getOrNull())
        settings.put(JUNIT_FAIL_ON_CVSS, config.junitFailOnCVSS.get())
        settings.put(FAIL_ON_UNUSED_SUPPRESSION_RULE, config.failBuildOnUnusedSuppressionRule.getOrNull())
        settings.put(HOSTED_SUPPRESSIONS_ENABLED, config.hostedSuppressions.enabled.getOrNull())
        settings.put(HOSTED_SUPPRESSIONS_FORCEUPDATE, config.hostedSuppressions.forceupdate.getOrNull())
        settings.put(HOSTED_SUPPRESSIONS_URL, config.hostedSuppressions.url.getOrNull())
        settings.put(HOSTED_SUPPRESSIONS_USER, config.hostedSuppressions.user.getOrNull())
        settings.put(HOSTED_SUPPRESSIONS_PASSWORD, config.hostedSuppressions.password.getOrNull())
        settings.put(HOSTED_SUPPRESSIONS_BEARER_TOKEN, config.hostedSuppressions.bearerToken.getOrNull())
        if (config.hostedSuppressions.validForHours.getOrNull() != null) {
            if (config.hostedSuppressions.validForHours.getOrNull() >= 0) {
                settings.put(HOSTED_SUPPRESSIONS_VALID_FOR_HOURS, config.hostedSuppressions.validForHours.getOrNull())
            } else {
                throw new InvalidUserDataException('Invalid setting: `validForHours` must be 0 or greater')
            }
        }
        settings.put(ANALYZER_JAR_ENABLED, config.analyzers.jarEnabled.getOrNull())
        settings.put(ANALYZER_NUSPEC_ENABLED, config.analyzers.nuspecEnabled.getOrNull())
        settings.put(ANALYZER_OSSINDEX_ENABLED, select(config.analyzers.ossIndex.enabled.getOrNull(), config.analyzers.ossIndexEnabled.getOrNull()))
        settings.put(ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, config.analyzers.ossIndex.warnOnlyOnRemoteErrors.getOrNull())
        settings.put(ANALYZER_OSSINDEX_ENABLED, config.analyzers.ossIndex.enabled.getOrNull())
        settings.put(ANALYZER_OSSINDEX_USER, config.analyzers.ossIndex.username.getOrNull() ?: null)
        settings.put(ANALYZER_OSSINDEX_PASSWORD, config.analyzers.ossIndex.password.getOrNull() ?: null)
        settings.put(ANALYZER_OSSINDEX_URL, config.analyzers.ossIndex.url.getOrNull() ?: null)

        settings.put(ANALYZER_CENTRAL_ENABLED, config.analyzers.centralEnabled.getOrNull())

        settings.put(ANALYZER_NEXUS_ENABLED, config.analyzers.nexusEnabled.getOrNull())
        settings.put(ANALYZER_NEXUS_URL, config.analyzers.nexusUrl.getOrNull() ?: null)
        settings.put(ANALYZER_NEXUS_USES_PROXY, config.analyzers.nexusUsesProxy.getOrNull())

        settings.put(ANALYZER_EXPERIMENTAL_ENABLED, config.analyzers.experimentalEnabled.getOrNull())
        settings.put(ANALYZER_ARCHIVE_ENABLED, config.analyzers.archiveEnabled.getOrNull())
        settings.put(ANALYZER_KNOWN_EXPLOITED_ENABLED, config.analyzers.kev.enabled.getOrNull())
        settings.put(KEV_URL, config.analyzers.kev.url.getOrNull())
        settings.put(KEV_CHECK_VALID_FOR_HOURS, config.analyzers.kev.validForHours.getOrNull())
        settings.put(KEV_USER, config.analyzers.kev.user.getOrNull())
        settings.put(KEV_PASSWORD, config.analyzers.kev.password.getOrNull())
        settings.put(KEV_BEARER_TOKEN, config.analyzers.kev.bearerToken.getOrNull())
        settings.put(ADDITIONAL_ZIP_EXTENSIONS, config.analyzers.zipExtensions.getOrNull() ?: null)
        settings.put(ANALYZER_ASSEMBLY_ENABLED, config.analyzers.assemblyEnabled.getOrNull())
        settings.put(ANALYZER_MSBUILD_PROJECT_ENABLED, config.analyzers.msbuildEnabled.getOrNull())
        settings.put(ANALYZER_ASSEMBLY_DOTNET_PATH, config.analyzers.pathToDotnet.getOrNull() ?: null)
        settings.put(ANALYZER_GOLANG_DEP_ENABLED, config.analyzers.golangDepEnabled.getOrNull())
        settings.put(ANALYZER_GOLANG_MOD_ENABLED, config.analyzers.golangModEnabled.getOrNull())
        settings.put(ANALYZER_GOLANG_PATH, config.analyzers.pathToGo.getOrNull())

        settings.put(ANALYZER_COCOAPODS_ENABLED, config.analyzers.cocoapodsEnabled.getOrNull())
        settings.put(ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED, config.analyzers.swiftEnabled.getOrNull())
        settings.put(ANALYZER_DART_ENABLED, config.analyzers.dartEnabled.getOrNull())
        settings.put(ANALYZER_SWIFT_PACKAGE_RESOLVED_ENABLED, config.analyzers.swiftPackageResolvedEnabled.getOrNull())
        settings.put(ANALYZER_BUNDLE_AUDIT_ENABLED, config.analyzers.bundleAuditEnabled.getOrNull())
        settings.put(ANALYZER_BUNDLE_AUDIT_PATH, config.analyzers.pathToBundleAudit.getOrNull() ?: null)

        settings.put(ANALYZER_PYTHON_DISTRIBUTION_ENABLED, config.analyzers.pyDistributionEnabled.getOrNull())
        settings.put(ANALYZER_PYTHON_PACKAGE_ENABLED, config.analyzers.pyPackageEnabled.getOrNull())
        settings.put(ANALYZER_RUBY_GEMSPEC_ENABLED, config.analyzers.rubygemsEnabled.getOrNull())
        settings.put(ANALYZER_OPENSSL_ENABLED, config.analyzers.opensslEnabled.getOrNull())
        settings.put(ANALYZER_CMAKE_ENABLED, config.analyzers.cmakeEnabled.getOrNull())
        settings.put(ANALYZER_AUTOCONF_ENABLED, config.analyzers.autoconfEnabled.getOrNull())
        settings.put(ANALYZER_COMPOSER_LOCK_ENABLED, config.analyzers.composerEnabled.getOrNull())
        settings.put(ANALYZER_COMPOSER_LOCK_SKIP_DEV, config.analyzers.composerSkipDev.getOrNull())
        settings.put(ANALYZER_CPANFILE_ENABLED, config.analyzers.cpanEnabled.getOrNull())
        settings.put(ANALYZER_NUGETCONF_ENABLED, config.analyzers.nugetconfEnabled.getOrNull())

        settings.put(ANALYZER_NODE_PACKAGE_ENABLED, select(config.analyzers.nodePackage.enabled.getOrNull(), config.analyzers.nodeEnabled.getOrNull()))
        settings.put(ANALYZER_NODE_PACKAGE_SKIPDEV, config.analyzers.nodePackage.skipDevDependencies.getOrNull())
        settings.put(ANALYZER_NODE_AUDIT_ENABLED, select(config.analyzers.nodeAudit.enabled.getOrNull(), config.analyzers.nodeAuditEnabled.getOrNull()))
        settings.put(ANALYZER_NODE_AUDIT_USE_CACHE, config.analyzers.nodeAudit.useCache.getOrNull())
        settings.put(ANALYZER_NODE_AUDIT_SKIPDEV, config.analyzers.nodeAudit.skipDevDependencies.getOrNull())
        settings.put(ANALYZER_NODE_AUDIT_URL, config.analyzers.nodeAudit.url.getOrNull() ?: null)
        settings.put(ANALYZER_YARN_AUDIT_ENABLED, config.analyzers.nodeAudit.yarnEnabled.getOrNull())
        settings.put(ANALYZER_YARN_PATH, config.analyzers.nodeAudit.yarnPath.getOrNull());
        settings.put(ANALYZER_PNPM_AUDIT_ENABLED, config.analyzers.nodeAudit.pnpmEnabled.getOrNull())
        settings.put(ANALYZER_PNPM_PATH, config.analyzers.nodeAudit.pnpmPath.getOrNull());
        settings.put(ANALYZER_RETIREJS_ENABLED, config.analyzers.retirejs.enabled.getOrNull())
        settings.put(ANALYZER_RETIREJS_FORCEUPDATE, config.analyzers.retirejs.forceupdate.getOrNull())
        settings.put(ANALYZER_RETIREJS_REPO_JS_URL, config.analyzers.retirejs.retireJsUrl.getOrNull())
        settings.put(ANALYZER_RETIREJS_REPO_JS_USER, config.analyzers.retirejs.user.getOrNull())
        settings.put(ANALYZER_RETIREJS_REPO_JS_PASSWORD, config.analyzers.retirejs.password.getOrNull())
        settings.put(ANALYZER_RETIREJS_REPO_JS_BEARER_TOKEN, config.analyzers.retirejs.bearerToken.getOrNull())
        settings.put(ANALYZER_RETIREJS_FILTER_NON_VULNERABLE, config.analyzers.retirejs.filterNonVulnerable.getOrNull())
        settings.put(ANALYZER_RETIREJS_FILTERS, config.analyzers.retirejs.filters.getOrElse([]))

        settings.put(ANALYZER_ARTIFACTORY_ENABLED, config.analyzers.artifactory.enabled.getOrNull())
        settings.put(ANALYZER_ARTIFACTORY_PARALLEL_ANALYSIS, config.analyzers.artifactory.parallelAnalysis.getOrNull())
        settings.put(ANALYZER_ARTIFACTORY_USES_PROXY, config.analyzers.artifactory.usesProxy.getOrNull())
        settings.put(ANALYZER_ARTIFACTORY_URL, config.analyzers.artifactory.url.getOrNull())
        settings.put(ANALYZER_ARTIFACTORY_API_TOKEN, config.analyzers.artifactory.apiToken.getOrNull())
        settings.put(ANALYZER_ARTIFACTORY_API_USERNAME, config.analyzers.artifactory.username.getOrNull())
        settings.put(ANALYZER_ARTIFACTORY_BEARER_TOKEN, config.analyzers.artifactory.bearerToken.getOrNull())

        settings.put(ANALYZER_NODE_AUDIT_USE_CACHE, config.cache.nodeAudit.getOrNull())
        settings.put(ANALYZER_CENTRAL_USE_CACHE, config.cache.central.getOrNull())
        settings.put(ANALYZER_OSSINDEX_USE_CACHE, config.cache.ossIndex.getOrNull())

        settings.removeAll { it.value == null }
        settings
    }

    private void configureSlack(Map<String, Object> settings, DependencyCheckExtension config) {
        settings.put(SlackNotificationSenderService.SLACK__WEBHOOK__ENABLED, config.slack.enabled.getOrNull())
        settings.put(SlackNotificationSenderService.SLACK__WEBHOOK__URL, config.slack.webhookUrl.getOrNull() ?: null)
    }

    private void configureProxy(Map<String, Object> settings, DependencyCheckExtension config) {
        String proxyHost = System.getProperty("https.proxyHost", System.getProperty("http.proxyHost"))
        String proxyPort = System.getProperty("https.proxyPort", System.getProperty("http.proxyPort"))
        String nonProxyHosts = System.getProperty("https.nonProxyHosts", System.getProperty("http.nonProxyHosts"))
        String proxyUser = System.getProperty("https.proxyUser", System.getProperty("http.proxyUser"))
        String proxyPassword = System.getProperty("https.proxyPassword", System.getProperty("http.proxyPassword"))

        if (proxyPort) {
            try {
                proxyPort = Integer.parseInt(proxyPort).toString()
            } catch (NumberFormatException nfe) {
                logger.warn("Unable to convert the configured `http.proxyPort` to a number: ${proxyPort}");
                proxyPort = null
            }
        }

        settings.put(PROXY_SERVER, proxyHost ?: config.proxy.server.getOrNull() ?: null)
        settings.put(PROXY_PORT, proxyPort ?: config.proxy.port.getOrNull()?.toString())
        settings.put(PROXY_USERNAME, proxyUser ?: config.proxy.username.getOrNull() ?: null)
        settings.put(PROXY_PASSWORD, proxyPassword ?: config.proxy.password.getOrNull() ?: null)
        def nonProxyHostsList = nonProxyHosts ? nonProxyHosts.tokenize("|") : config.proxy.nonProxyHosts.getOrElse([])
        settings.put(PROXY_NON_PROXY_HOSTS, nonProxyHostsList ? nonProxyHostsList.join("|") : null)
    }

    /**
     * Combines the configured suppressionFile and suppressionFiles into a
     * single array.
     *
     * @return an array of suppression file paths
     */
    private String[] determineSuppressions(Collection<String> suppressionFiles, String suppressionFile) {
        List<String> files = []
        if (suppressionFiles != null) {
            for (String sf : suppressionFiles) {
                files.add(sf.toString())
            }
        }
        if (suppressionFile != null) {
            files.add(suppressionFile)
        }
        return files.toArray(new String[0])
    }
    /**
     * Selects the current configiguration option - returns the deprecated option if the current configuration option is null
     * @param current the current configuration
     * @param deprecated the deprecated configuration
     * @return the current configuration option if not null; otherwise the deprecated option is returned
     */
    private Boolean select(Boolean current, Boolean deprecated) {
        return current != null ? current : deprecated
    }
}
