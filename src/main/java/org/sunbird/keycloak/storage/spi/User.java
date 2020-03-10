package org.sunbird.keycloak.storage.spi;

import java.util.List;
import java.util.Map;

public class User {

	private String id;
	private String username;
	private Boolean enabled;
	private Boolean emailVerified;
	private String firstName;
	private String lastName;
	private String email;
	private List<String> requiredActions;
	private List<Map<String, String>> credentials;
	
	

	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public Boolean isEnabled() {
		return enabled;
	}
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	public Boolean isEmailVerified() {
		return emailVerified;
	}
	public void setEmailVerified(Boolean emailVerified) {
		this.emailVerified = emailVerified;
	}
	public String getFirstName() {
		return firstName;
	}
	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}
	public String getLastName() {
		return lastName;
	}
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public List<String> getRequiredActions() {
		return requiredActions;
	}
	public void setRequiredActions(List<String> requiredActions) {
		this.requiredActions = requiredActions;
	}
	public List<Map<String, String>> getCredentials() {
		return credentials;
	}
	public void setCredentials(List<Map<String, String>> credentials) {
		this.credentials = credentials;
	}
	
	
}
