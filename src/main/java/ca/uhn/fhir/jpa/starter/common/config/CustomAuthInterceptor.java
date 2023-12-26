package ca.uhn.fhir.jpa.starter.common.config;

import ca.uhn.fhir.i18n.Msg;
import ca.uhn.fhir.jpa.starter.Application;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;

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

			Claims claims = null;
			try {
				claims = Jwts.parser()
					.setSigningKey(secretKey.getBytes(StandardCharsets.UTF_8))
					.parseClaimsJws(token)
					.getBody();
			}catch (MalformedJwtException malformedJwtException){
				throw new AuthenticationException(Msg.code(401) + "Invalid token.");
			} catch (ExpiredJwtException expiredJwtException){
				throw new AuthenticationException(Msg.code(401) + "Token expired.");
			}

			if (claims.getExpiration().after(new Date())){
				var userId = claims.get("user_id");
				if (checkUserExistsInDatabase(userId.toString()) == -1){
					logger.info("NotExist");
					throw new AuthenticationException(Msg.code(404) + "User does not exist");
				}

				if (checkUserExistsInDatabase(userId.toString()) > 0){
					RuleBuilder ruleBuilder = new RuleBuilder();
					List<String> roles = (List<String>) claims.get("roles");
					logger.info("---- " + roles);
					if (roles.size()<0)
						return new RuleBuilder().denyAll().build();
					for (String role: roles) {
						switch (role) {
							case "nurse":
								ruleBuilder.allow().create().allResources().withAnyId().andThen()
									.allow().read().allResources().withAnyId().andThen()
									.deny().create().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.deny().write().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.deny().delete().allResources().withAnyId();
								break;
							case "224608005":
							case "224529009":
							case "6868009":
							case "doctor":
							case "ict":
								ruleBuilder.allowAll().build();
								break;
							case "pharmacist":
								ruleBuilder.allow().create().resourcesOfType("Medication").withAnyId().andThen()
									.allow().write().resourcesOfType("Medication").withAnyId().andThen()
									.allow().read().allResources().withAnyId().andThen()
									.deny().create().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
									.deny().write().resourcesOfType("Practitioner, PractitionerRole, Organization").withAnyId().andThen()
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
					return ruleBuilder.build();
				}else{
					logger.info("User exist. but is inactive");
					throw new AuthenticationException(Msg.code(401) + "Unauthorised");
				}
			} else{
				throw new AuthenticationException(Msg.code(401) + "Token expired.");
			}
		}else {
			throw new AuthenticationException(Msg.code(403) + "No token provided.");
		}
	}

	private int checkUserExistsInDatabase(String userId) {

		String sql1 = "SELECT count(*) FROM hfj_res_ver\n" +
			"WHERE res_id = " + userId + " AND res_ver = (SELECT MAX(res_ver) FROM hfj_res_ver WHERE res_id = " + userId + ")\n" +
			"AND res_text_vc LIKE '%\"active\":true%';";

		String sql2 = "SELECT count(*) FROM hfj_res_ver\n" +
			"WHERE res_id = " + userId + " AND res_ver = (SELECT MAX(res_ver) FROM hfj_res_ver WHERE res_id = " + userId + ")\n" +
			"AND res_text_vc LIKE '%\"active\":false%';";

		try (Connection conn = DriverManager.getConnection(url, username, password);
			  PreparedStatement pstmt1 = conn.prepareStatement(sql1);
			  PreparedStatement pstmt2 = conn.prepareStatement(sql2);
			  ResultSet rs1 = pstmt1.executeQuery();
			  ResultSet rs2 = pstmt2.executeQuery()) {
			if (rs1.next() && rs1.getInt(1)==1){
				return 1;  //If user exist
			}
			if (rs2.next() && rs2.getInt(1)==1){
				return 0; //If user exist, but is inactive
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
		return -1; //If user exist, not exist
	}
}