package com.sid.secservic.sec.repo;

import com.sid.secservic.sec.entity.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

public interface AppUserRepository extends JpaRepository<AppUser, Long > {
    AppUser findByUsername(String username);

}
