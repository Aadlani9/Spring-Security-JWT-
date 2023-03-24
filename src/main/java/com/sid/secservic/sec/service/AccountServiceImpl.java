package com.sid.secservic.sec.service;


import com.sid.secservic.sec.entity.AppRole;
import com.sid.secservic.sec.entity.AppUser;
import com.sid.secservic.sec.repo.AppRoleRepository;
import com.sid.secservic.sec.repo.AppUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class AccountServiceImpl implements AccountService {
    private final AppUserRepository appUserRepo;
    private final AppRoleRepository appRoleRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public AppUser addNewUser(AppUser appUser) {
        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        return appUserRepo.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepo.save(appRole);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser = appUserRepo.findByUsername(username);
        AppRole appRole = appRoleRepo.findByRoleName(roleName);
        appUser.getAppRoles().add(appRole);
    }
    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepo.findByUsername(username);
    }

    @Override
    public List<AppUser> listUsers() {
        return appUserRepo.findAll();
    }
}
