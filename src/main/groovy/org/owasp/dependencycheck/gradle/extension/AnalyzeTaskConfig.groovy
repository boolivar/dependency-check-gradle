package org.owasp.dependencycheck.gradle.extension

import org.gradle.api.NamedDomainObjectContainer
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.MapProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Nested
import org.gradle.api.tasks.Optional

abstract class AnalyzeTaskConfig {
    @Input
    abstract Property<Boolean> getSkip()
    @Input
    abstract ListProperty<String> getAnalyzedTypes()
    @Input
    abstract Property<Boolean> getFailOnError()
    @Optional
    @Input
    abstract Property<String> getFormat()
    @Input
    abstract ListProperty<String> getFormats()
    @Input
    abstract Property<Boolean> getScanBuildEnv()
    @Input
    abstract Property<Boolean> getScanDependencies()
    @Input
    abstract ListProperty<String> getScanConfigurations()
    @Input
    abstract ListProperty<String> getSkipConfigurations()
    @Input
    abstract ListProperty<String> getScanProjects()
    @Input
    abstract ListProperty<String> getSkipProjects()
    @Input
    abstract Property<Boolean> getShowSummary()
    @Input
    abstract Property<Number> getFailBuildOnCVSS()
    @Input
    abstract ListProperty<String> getSkipGroups()
    @Input
    abstract Property<Boolean> getSkipTestGroups()
    @InputFiles
    abstract ConfigurableFileCollection getScanSet()
    @Nested
    abstract NamedDomainObjectContainer<AdditionalCpe> getAdditionalCpes()
    @Input
    abstract MapProperty<String, Object> getSettings()
    @Internal
    boolean isScanSetConfigured() {
        !scanSet.empty
    }
}
