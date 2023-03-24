package com.sid.secservic.sec.web;

import com.sid.secservic.sec.entity.AppRole;
import com.sid.secservic.sec.entity.AppUser;
import com.sid.secservic.sec.service.AccountService;
import lombok.Data;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class AccountRestController {

    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path = "/users")
    public List<AppUser> appUsers(){
        return accountService.listUsers();
    }

    @PostMapping(path = "/users")
    public  AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    @PostMapping(path = "/roles")
    public AppRole saveRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    @PostMapping(path = "/addRoleToUser")
    public void addRoleToUser( @RequestBody RoleToUserForm roleToUserForm){
        accountService.addRoleToUser(roleToUserForm.getUsername(), roleToUserForm.getRolename());
    }
}

@Data
class RoleToUserForm {
    private String username;
    private String rolename;
}
