package ca.uhn.fhir.jpa.starter.common.config;

import ca.uhn.fhir.i18n.Msg;
import ca.uhn.fhir.jpa.starter.Application;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.Date;
import java.util.List;

@SuppressWarnings("ConstantConditions")
public class CustomAuthInterceptor extends AuthorizationInterceptor {

	final String secretKey = "She saw a sea shell on the sea shore";

	final String url = "jdbc:postgresql://134.209.154.146:5432/mdrdev";

	final String username = "postgres";

	final String password = "Fhir@123";

	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(Application.class);

	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
		String authorizationHeader = theRequestDetails.getHeader("Authorization");

		if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
			final var token = authorizationHeader.substring(7);

			Claims claims = Jwts.parser()
				.setSigningKey(secretKey.getBytes(StandardCharsets.UTF_8))
				.parseClaimsJws(token)
				.getBody();

			if (claims.getExpiration().after(new Date())){
				var userId = claims.get("user_id");
				if (checkUserExistsInDatabase(userId.toString())){
					logger.info("UserExist");
					RuleBuilder ruleBuilder = new RuleBuilder();
					List<String> roles = (List<String>) claims.get("roles");
					logger.info("---- " + roles);
					if (roles.size()<0)
						return new RuleBuilder().denyAll().build();
					for (String role: roles) {
						switch (role) {
							case "doctor":
								ruleBuilder.allow().create().resourcesOfType("MedicationRequest").withAnyId().andThen()
									.allow().write().resourcesOfType("MedicationRequest").withAnyId().andThen()
									.allow().read().allResources().withAnyId().andThen()
									.deny().create().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.deny().write().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.deny().delete().allResources().withAnyId();
								break;
							case "nurse":
								ruleBuilder.allow().create().allResources().withAnyId().andThen()
									.allow().read().allResources().withAnyId().andThen()
									.deny().create().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.deny().write().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.deny().delete().allResources().withAnyId();
								break;
							case "pharmacist":
								ruleBuilder.allow().create().resourcesOfType("Medication").withAnyId().andThen()
									.allow().write().resourcesOfType("Medication").withAnyId().andThen()
									.allow().read().allResources().withAnyId().andThen()
									.deny().create().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.deny().write().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.deny().delete().allResources().withAnyId();
								break;
							case "ict":		// Role: Front-office staff/Admin
								ruleBuilder.allow().create().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.allow().write().resourcesOfType("Medication").withAnyId().andThen()
									.allow().read().allResources().withAnyId().andThen()
									.deny().create().resourcesOfType("Medication, MedicationRequest").withAnyId().andThen()
									.deny().write().resourcesOfType("Medication, MedicationRequest").withAnyId().andThen()
									.deny().delete().allResources().withAnyId();
								break;
							case "307988006":		// Role: Lab technician
								ruleBuilder.allow().create().resourcesOfType("Observation").withAnyId().andThen()
									.allow().write().resourcesOfType("Observation").withAnyId().andThen()
									.allow().read().allResources().withAnyId().andThen()
									.deny().create().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.deny().write().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.deny().delete().allResources().withAnyId();
								break;
							case "397897005":		// Role: Paramedics
								ruleBuilder.allow().create().resourcesOfType("Medication, MedicationRequest").withAnyId().andThen()
									.allow().write().resourcesOfType("Medication, MedicationRequest").withAnyId().andThen()
									.allow().read().allResources().withAnyId().andThen()
									.deny().create().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.deny().write().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.deny().delete().allResources().withAnyId();
								break;
						}
					}
					logger.info("----- " + ruleBuilder.build().toString());
					return ruleBuilder.build();
				}else{
					logger.info("NotExist");
					throw new AuthenticationException(Msg.code(404) + "User does not exist");
				}
			} else{
				throw new AuthenticationException(Msg.code(401) + "Provided token is expired");
			}
		}else {
			return new RuleBuilder().denyAll().build();
		}
	}

	private boolean checkUserExistsInDatabase(String userId) {

		String sql = "SELECT count(*) FROM hfj_res_ver WHERE res_id = "  +userId;

		try (Connection conn = DriverManager.getConnection(url, username, password);
			  PreparedStatement pstmt = conn.prepareStatement(sql);
			  ResultSet rs = pstmt.executeQuery()) {
			if (rs.next()){
				int count = rs.getInt(1);
				return count>0;
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
		return false;
	}
}