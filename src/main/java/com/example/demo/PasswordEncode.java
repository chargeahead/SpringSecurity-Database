package com.example.demo;


import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordEncode {

  public static void main(String[] args) {
		String password = "dev";
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		String hashedPassword = passwordEncoder.encode(password);

		System.out.println(hashedPassword);
		password = "admin";
		hashedPassword = passwordEncoder.encode(password);

		System.out.println(hashedPassword);
	}

  }

