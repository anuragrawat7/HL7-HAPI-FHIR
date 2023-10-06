package ca.uhn.fhir.jpa.starter.common.config;

import ca.uhn.fhir.i18n.Msg;
import ca.uhn.fhir.jpa.starter.Application;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;

import java.util.List;

@SuppressWarnings("ConstantConditions")
public class CustomAuthInterceptor extends AuthorizationInterceptor {
	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(Application.class);

	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {

		boolean userIsAdmin = false;
		String authHeader = theRequestDetails.getHeader("Authorization");
		if ("Bearer eyJhbGciOiJIUzUxMiOTWv4R".equals(authHeader)) {
			// This user has access to everything
			userIsAdmin = true;
		} else {
			// Throw an HTTP 401
			throw new AuthenticationException(Msg.code(401) + "Missing or invalid Authorization header value");
		}

		// If the user is an admin, allow everything
		if (userIsAdmin) {
			return new RuleBuilder().allowAll().build();
		}

		// By default, deny everything. This should never get hit, but it's
		// good to be defensive
		return new RuleBuilder().denyAll().build();
	}
}
