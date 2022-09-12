package fr.insee.keycloak.mapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.keycloak.broker.oidc.KeycloakOIDCIdentityProvider;
import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.mappers.AbstractClaimMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.JsonWebToken;

public final class ExternalKeycloakRolesToRolesMapper extends AbstractClaimMapper {

    public static final String[] COMPATIBLE_PROVIDERS = { KeycloakOIDCIdentityProviderFactory.PROVIDER_ID,
            OIDCIdentityProviderFactory.PROVIDER_ID };

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    private static final String CLAIMS_NAME = "claims.name";
    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(
            Arrays.asList(IdentityProviderSyncMode.values()));

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(CLAIMS_NAME);
        property.setLabel("Path to external claims");
        property.setHelpText(
                "Path to external claims to add to user roles, for example realm_access.roles or resource_access.(.*).roles");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("realm_access.roles");
        configProperties.add(property);
    }

    public static final String PROVIDER_ID = "keycloak-oidc-roles-to-roles-idp-mapper";

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Role Importer";
    }

    @Override
    public String getDisplayType() {
        return "External Roles to Roles";
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String claimsName = mapperModel.getConfig().get(CLAIMS_NAME);
        List<String> rolesToAdd = extractClaims(claimsName, context);
        getRoleModelFromRoleList(rolesToAdd, realm).forEach(user::grantRole);
    }

    @Override
    public void updateBrokeredUserLegacy(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        // The legacy mapper actually did nothing although it pretended to do something
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String claimsName = mapperModel.getConfig().get(CLAIMS_NAME);
        List<String> rolesToAdd = extractClaims(claimsName, context);
        Stream<RoleModel> rolesToRemove = user.getRoleMappingsStream()
                .filter(role -> !rolesToAdd.contains(role.getName()));
        rolesToRemove.forEach(roleModel -> user.deleteRoleMapping(roleModel));
        getRoleModelFromRoleList(rolesToAdd, realm).forEach(user::grantRole);
    }

    @Override
    public String getHelpText() {
        return "Looks for an external role in a keycloak access token.  If external role exists, grant the user the specified realm or client role.";
    }

    private List<String> extractClaims(String claimsName, BrokeredIdentityContext context) {
        JsonWebToken token = (JsonWebToken) context.getContextData()
                .get(KeycloakOIDCIdentityProvider.VALIDATED_ACCESS_TOKEN);
        Object claims = getClaimValue(token, claimsName);
        return extractValue(claims);
    }

    private List<RoleModel> getRoleModelFromRoleList(List<String> roles, RealmModel realm) {
        return roles.stream().map(role -> KeycloakModelUtils.getRoleFromString(realm, role))
                .collect(Collectors.toList());
    }

    private List<String> extractValue(Object value) {
        List<String> result = new ArrayList<>();
        if (value instanceof String) {
            result.add((String) value);
        } else if (value instanceof Double) {
            try {
                result.add((String) value);
            } catch (Exception e) {

            }
        } else if (value instanceof Integer) {
            try {
                result.add((String) value);
            } catch (Exception e) {

            }
        } else if (value instanceof Boolean) {
            try {
                result.add((String) value);
            } catch (Exception e) {

            }
        } else if (value instanceof List) {
            List list = (List) value;
            for (Object val : list) {
                result.add((String) val);
            }
        }
        return result;
    }
}
