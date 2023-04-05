package com.sid.secservic.sec.service;

import com.sid.secservic.sec.entity.AppRole;
import com.sid.secservic.sec.entity.AppUser;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username, String roleName);
    UserDetails loadUserByUsername(String username);
    AppUser findUserByUsername(String username);
    List<AppUser> listUsers();
}
