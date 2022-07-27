package com.pathfinderapps.mwauthentication.service;

import java.security.Key;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.transaction.Transactional;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.pathfinderapps.mwauthentication.model.Role;
import com.pathfinderapps.mwauthentication.model.User;
import com.pathfinderapps.mwauthentication.repo.RoleRepo;
import com.pathfinderapps.mwauthentication.repo.UserRepo;



@Service @Transactional @RequiredArgsConstructor @Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

	private final UserRepo userRepo;
	private final RoleRepo roleRepo;
	private final PasswordEncoder passwordEncoder;

	@Override
	public User saveUser(User user) {
		log.info("Saving new user {} to the database", user.getUsername());
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return userRepo.save(user);
	}

	@Override
	public Role saveRole(Role role) {
		log.info("Saving new role {} to the database", role.getName());
		return roleRepo.save(role);
	}

	@Override
	public void addRoleToUser(String username, String roleName) {
		log.info("Adding new role {} to the user {}", roleName,username);
		User user = userRepo.findByUsername(username);
		Role role = roleRepo.findByName(roleName);
		user.getRoles().add(role);
	}

	@Override
	public User getUser(String username) {
		log.info("Fetching User {}",username);
		return userRepo.findByUsername(username);
	}

	@Override
	public List<User> getUsers() {
		log.info("Fetching all users");
		return userRepo.findAll();
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepo.findByUsername(username);
		if(user == null){
			log.error("User {} not found in database", username);
			throw new UsernameNotFoundException("User Not Found in the database");
		} else{
			log.info("User {} found in the database", username);
		}
		log.info(user.getPassword());
		Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
		user.getRoles().forEach( role -> {
			authorities.add(new SimpleGrantedAuthority(role.getName()));
		});
		return new org.springframework.security.core.userdetails.User(user.getUsername(),user.getPassword(),authorities);
	}

	@Override
	public Map<String,String> login(String username, String password) throws Exception {
		Map<String,String> map = new HashMap<>();
		log.info("Username is: {}", username); log.info("Password is: {}", password);
		User user = userRepo.findByUsername(username);
		if(user == null){
			log.error("User not found!");
		} else if(!passwordEncoder.matches(password,user.getPassword())) {
			log.error("User found but Incorrect password!");
		}
		else{
			map.put("username",encrypt(user.getUsername()));
			map.put("password",encrypt(user.getUsername()));
			map.put("roles",encrypt(user.getRoles().toString()));
		}
		return map;
	}

	private final String key = "065580b48e436926b2885a808babdfas";
	private byte[] keyValue;
	private final String ALGO = "AES";

	private String encrypt(String jwt) throws Exception {

		keyValue = key.getBytes();

		Key key = new SecretKeySpec(keyValue, ALGO);
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] encVal = c.doFinal(jwt.getBytes());
		String encryptedValue = Base64.getEncoder().encodeToString(encVal);
		return encryptedValue;
	}

	private String decrypt(String encryptedData) throws Exception {
		Key key = new SecretKeySpec(keyValue, ALGO);
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] decodedValue = Base64.getDecoder().decode(encryptedData);
		byte[] decValue = c.doFinal(decodedValue);
		String decryptedValue = new String(decValue);
		return decryptedValue;
	}
}
