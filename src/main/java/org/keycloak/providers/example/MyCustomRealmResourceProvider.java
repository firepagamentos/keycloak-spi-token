package org.keycloak.providers.example;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.services.resource.RealmResourceProvider;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.aerogear.security.otp.Totp;
import org.keycloak.TokenVerifier;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.credential.OTPCredentialProvider;


import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;


/**
 *
 * @author <a href="mailto:svacek@redhat.com">Simon Vacek</a>
 */
public class MyCustomRealmResourceProvider  implements RealmResourceProvider {

    private final KeycloakSession session;

    public MyCustomRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    public OTPCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (OTPCredentialProvider)session.getProvider(CredentialProvider.class, "keycloak-otp");
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }

    @GET
    @Path("hello")
    @Produces(MediaType.TEXT_PLAIN)
    public Response hello() {
        return Response.ok("Hello World!").type(MediaType.TEXT_PLAIN).build();
    }

    @POST
    @Path("credential-validation")
    @NoCache
    @Consumes("application/json")
    @Produces("application/json")
    public Response validateOtp(String jsonPayload, @Context HttpHeaders headers) {

        try {
            // 1. Extrai o payload JSON
            ObjectMapper mapper = new ObjectMapper();
            List<CredentialInput> credentials = mapper.readValue(jsonPayload,
                    new TypeReference<List<CredentialInput>>() {
                    });

            if (credentials.isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"valid\": false, \"error\": \"Empty credentials\"}")
                        .build();
            }

            CredentialInput input = credentials.get(0);

            if (!"totp".equalsIgnoreCase(input.getType())) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"valid\": false, \"error\": \"Unsupported credential type\"}")
                        .build();
            }

            // 2. Extrai o token do header Authorization
            String authHeader = headers.getHeaderString("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("{\"valid\": false, \"error\": \"Missing or invalid Authorization header\"}")
                        .build();
            }
            String tokenString = authHeader.substring("Bearer ".length()).trim();

            // 3. Valida o access token
            AccessToken accessToken;
            try {
                TokenVerifier<AccessToken> tokenVerifier = TokenVerifier.create(tokenString, AccessToken.class);
                accessToken = tokenVerifier.getToken();
            } catch (Exception e) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("{\"valid\": false, \"error\": \"Invalid access token: " + e.getMessage() + "\"}")
                        .build();
            }

            // 4. Recupera o usuário
            String userId = accessToken.getSubject();
            UserModel user = session.users().getUserById(session.getContext().getRealm(), userId);
            if (user == null) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("{\"valid\": false, \"error\": \"User not found\"}")
                        .build();
            }

            // 5. Verifica se o usuário tem credenciais OTP configuradas
            OTPCredentialProvider otpProvider = (OTPCredentialProvider) session.getProvider(CredentialProvider.class, "keycloak-otp");
            OTPCredentialModel defaultOTPCredential = otpProvider.getDefaultCredential(session, session.getContext().getRealm(), user);

            if (defaultOTPCredential == null) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"valid\": false, \"error\": \"OTP credential not configured for user\"}")
                        .build();
            }

            // 6. Valida o código OTP fornecido pelo usuário
            String otpInput = input.getValue();  // Supondo que o OTP seja passado como parte do input
            boolean valid = otpProvider.isValid(session.getContext().getRealm(), user, new UserCredentialModel(defaultOTPCredential.getId(), OTPCredentialModel.TYPE, otpInput));

            if (!valid) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("{\"valid\": false, \"error\": \"Invalid OTP\"}")
                        .build();
            }

            // 7. Retorna sucesso se o OTP for válido
            return Response.ok("{\"valid\": true}").build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"valid\": false, \"error\": \"" + e.getMessage() + "\"}")
                    .build();
        }
    }

    public static class CredentialInput {
        private String type;
        private String value;

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }
}


