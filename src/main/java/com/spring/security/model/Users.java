package com.spring.security.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Entity
@Table(name = "users")
@Data
public class Users {

	public Users() {

	}

	public Users(@NotNull(message = "Required") String username, @NotNull(message = "Required") String password) {
		super();
		this.username = username;
		this.password = password;
	}
	
	@Id
	@Column(name = "id")
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;

	@Column(name = "username")
	@NotNull(message = "Required")
	private String username;

	@Column(name = "password")
	@NotNull(message = "Required")
	private String password;
}
