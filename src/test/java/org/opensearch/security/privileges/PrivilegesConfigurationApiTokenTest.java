/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.privileges;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

import com.google.common.collect.ImmutableSet;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.action.apitokens.ApiTokenRepository;
import org.opensearch.security.configuration.ConfigurationChangeListener;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.configuration.TokenListener;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;

import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class PrivilegesConfigurationApiTokenTest {

    private static final String CUSTOM_ACTION_GROUP = "custom_monitor";
    private static final String TOKEN_USER = "token:alpha";
    private static final String ACTION = "cluster:monitor/state";

    private ConfigurationRepository configurationRepository;
    private ApiTokenRepository apiTokenRepository;
    private final Map<String, RoleV7> knownTokens = new HashMap<>();
    private final Map<CType<?>, SecurityDynamicConfiguration<?>> configurations = new HashMap<>();
    private TokenListener tokenListener;
    private ConfigurationChangeListener configurationListener;
    private PrivilegesConfiguration privilegesConfiguration;

    @Before
    public void setUp() throws Exception {
        configurationRepository = mock(ConfigurationRepository.class);
        when(configurationRepository.getConfiguration(any())).thenAnswer(invocation -> {
            CType<?> type = invocation.getArgument(0);
            SecurityDynamicConfiguration<?> configuration = configurations.get(type);
            return configuration != null ? configuration : SecurityDynamicConfiguration.empty(type);
        });
        configurations.put(CType.CONFIG, SecurityDynamicConfiguration.fromYaml("""
            _meta:
              type: "config"
              config_version: 2
            config:
              dynamic: {}
            """, CType.CONFIG));

        apiTokenRepository = mock(ApiTokenRepository.class);
        doAnswer(invocation -> {
            BiConsumer<String, RoleV7> consumer = invocation.getArgument(0);
            knownTokens.forEach(consumer);
            return null;
        }).when(apiTokenRepository).forEachToken(any());

        ClusterState clusterState = mock(ClusterState.class, Mockito.RETURNS_DEEP_STUBS);
        ClusterService clusterService = mock(ClusterService.class);
        when(clusterService.getClusterSettings()).thenReturn(
            new ClusterSettings(Settings.EMPTY, ClusterSettings.BUILT_IN_CLUSTER_SETTINGS)
        );
        PrivilegesEvaluator.CoreDependencies coreDependencies = new PrivilegesEvaluator.CoreDependencies(
            clusterService,
            () -> clusterState,
            null,
            null,
            null,
            null,
            null,
            Settings.EMPTY,
            null,
            () -> "not initialized",
            NamedXContentRegistry.EMPTY,
            apiTokenRepository
        );

        privilegesConfiguration = new PrivilegesConfiguration(configurationRepository, coreDependencies);

        ArgumentCaptor<TokenListener> tokenListenerCaptor = ArgumentCaptor.forClass(TokenListener.class);
        verify(apiTokenRepository).subscribeOnChange(tokenListenerCaptor.capture());
        tokenListener = tokenListenerCaptor.getValue();

        ArgumentCaptor<ConfigurationChangeListener> configurationListenerCaptor = ArgumentCaptor.forClass(
            ConfigurationChangeListener.class
        );
        verify(configurationRepository).subscribeOnChange(configurationListenerCaptor.capture());
        configurationListener = configurationListenerCaptor.getValue();
    }

    @Test
    public void tokensLoadedAfterTheConfiguration_getPrivileges() throws Exception {
        defineCustomActionGroup();
        configurationListener.onChange(null);

        addToken();
        tokenListener.onChange();

        assertTrue("the token must be allowed by the action group", isAllowed());
    }

    @Test
    public void tokensLoadedBeforeTheConfiguration_getPrivilegesWhenTheConfigurationArrives() throws Exception {
        addToken();
        tokenListener.onChange();
        assertFalse("without the action group, the token has no usable privileges", isAllowed());

        defineCustomActionGroup();
        configurationListener.onChange(null);

        assertTrue("the privileges must follow the configuration that arrived later", isAllowed());
    }

    @Test
    public void failingTokenPrivileges_doNotKeepTheConfigurationFromBeingApplied() throws Exception {
        doAnswer(invocation -> { throw new IllegalStateException("boom"); }).when(apiTokenRepository).forEachToken(any());

        defineCustomActionGroup();
        configurationListener.onChange(null);

        assertFalse(
            "the evaluator must have been initialized despite the failing token privileges",
            privilegesConfiguration.privilegesEvaluator() instanceof PrivilegesEvaluator.NotInitialized
        );
    }

    private void addToken() {
        RoleV7 role = new RoleV7();
        role.setCluster_permissions(List.of(CUSTOM_ACTION_GROUP));
        knownTokens.put(TOKEN_USER, role);
    }

    private void defineCustomActionGroup() throws Exception {
        configurations.put(CType.ACTIONGROUPS, SecurityDynamicConfiguration.fromYaml("""
            _meta:
              type: "actiongroups"
              config_version: 2
            custom_monitor:
              allowed_actions:
                - "cluster:monitor/state"
              type: "cluster"
            """, CType.ACTIONGROUPS));
    }

    private boolean isAllowed() {
        ActionPrivileges privileges = privilegesConfiguration.tokenPrivileges().get(TOKEN_USER);
        if (privileges == null) {
            return false;
        }
        PrivilegesEvaluationContext context = new PrivilegesEvaluationContext(
            new User(TOKEN_USER),
            ImmutableSet.of(),
            ACTION,
            null,
            ActionRequestMetadata.empty(),
            null,
            null,
            null,
            null,
            privileges,
            List.of()
        );
        return privileges.hasClusterPrivilege(context, ACTION).isAllowed();
    }
}
