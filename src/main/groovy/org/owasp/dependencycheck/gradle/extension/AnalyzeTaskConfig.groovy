package org.owasp.dependencycheck.gradle.extension

import org.gradle.api.NamedDomainObjectContainer
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Nested
import org.gradle.api.tasks.Optional

abstract class AnalyzeTaskConfig implements DependencyCheckTaskConfig {
    /**
     * If set to true dependency-check analysis will be skipped.
     */
    @Input
    abstract Property<Boolean> getSkip()
    /**
     * The default artifact types that will be analyzed.
     */
    @Input
    abstract ListProperty<String> getAnalyzedTypes()
    /**
     * The report format to be generated (HTML, XML, CSV, JSON, JUNIT, SARIF, JENKINS, GITLAB, ALL).
     */
    @Optional
    @Input
    abstract Property<String> getFormat()
    /**
     * A list of report formats to be generated (HTML, XML, CSV, JSON, JUNIT, SARIF, JENKINS, GITLAB, ALL).
     */
    @Input
    abstract ListProperty<String> getFormats()
    /**
     * A boolean indicating whether to scan the <i>buildEnv</i>.
     */
    @Input
    abstract Property<Boolean> getScanBuildEnv()
    /**
     * A boolean indicating whether to scan the <i>dependencies</i>.
     */
    @Input
    abstract Property<Boolean> getScanDependencies()
    /**
     * A list of configurations that will be scanned, all other configurations are skipped.
     * This is mutually exclusive with the {@link #getSkipConfigurations skipConfigurations} property.
     */
    @Input
    abstract ListProperty<String> getScanConfigurations()
    /**
     * A list of configurations that will be skipped.
     * This is mutually exclusive with the {@link #getScanConfigurations scanConfigurations} property.
     */
    @Input
    abstract ListProperty<String> getSkipConfigurations()
    /**
     * A list of projects that will be scanned, all other projects are skipped.
     * The list or projects to skip must include a preceding colon: <code>scanProjects = [':app']</code>.
     * This is mutually exclusive with the {@link #getSkipProjects skipProjects} property.
     */
    @Input
    abstract ListProperty<String> getScanProjects()
    /**
     * A list of projects that will be skipped.
     * The list or projects to skip must include a preceding colon: <code>skipProjects = [':sub1']</code>.
     * This is mutually exclusive with the {@link #getScanProjects scanProjects} property.
     */
    @Input
    abstract ListProperty<String> getSkipProjects()
    /**
     * Displays a summary of the findings.
     */
    @Input
    abstract Property<Boolean> getShowSummary()
    /**
     * Specifies if the build should be failed if a CVSS score equal to or above a specified level is identified.
     */
    @Input
    abstract Property<Number> getFailBuildOnCVSS()
    /**
     * Group prefixes of the modules to skip when scanning.
     * The 'project' prefix can be used to skip all internal dependencies from multi-project build.
     */
    @Input
    abstract ListProperty<String> getSkipGroups()
    /**
     * When set to true all dependency groups that being with 'test' will be skipped.
     */
    @Input
    abstract Property<Boolean> getSkipTestGroups()
    /**
     * A list of directories that will be scanned for additional dependencies.
     */
    @InputFiles
    abstract ConfigurableFileCollection getScanSet()
    /**
     * Additional CPE to be analyzed.
     */
    @Nested
    abstract NamedDomainObjectContainer<AdditionalCpe> getAdditionalCpes()
    @Internal
    boolean isScanSetConfigured() {
        !scanSet.empty
    }
}
