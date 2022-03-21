package com.rocktech.jwt.repository;

import com.rocktech.jwt.model.ERole;
import com.rocktech.jwt.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
