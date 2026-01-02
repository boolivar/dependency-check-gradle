package org.owasp.dependencycheck.gradle.extension;

import org.gradle.api.provider.MapProperty;
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input;

interface DependencyCheckTaskConfig {
    /**
     * Fails the build if an error occurs during the task execution.
     */
    @Input
    abstract Property<Boolean> getFailOnError()
    /**
     * DependencyCheck Engine settings.
     * List of supported keys: {@link org.owasp.dependencycheck.utils.Settings.KEYS}
     * @see org.owasp.dependencycheck.utils.Settings
     */
    @Input
    MapProperty<String, Object> getSettings()
}
