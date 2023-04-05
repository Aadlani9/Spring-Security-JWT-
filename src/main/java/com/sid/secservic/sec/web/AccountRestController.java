package com.sid.secservic.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sid.secservic.sec.JWTUtil;
import com.sid.secservic.sec.entity.AppRole;
import com.sid.secservic.sec.entity.AppUser;
import com.sid.secservic.sec.service.AccountService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@RestController
@RequiredArgsConstructor @Slf4j
public class AccountRestController {

    private final AccountService accountService;

    @GetMapping(path = "/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers(){
        return accountService.listUsers();
    }

    @PostMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
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

    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception{
        String autToken = request.getHeader(AUTHORIZATION);
        if (autToken != null && autToken.startsWith("Bearer ") ) {
            try {
                String token = autToken.substring(7);
                Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(token);
                String username = decodedJWT.getSubject();

                AppUser appUser = accountService.findUserByUsername(username);

                String jwtAccessToken = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + JWTUtil.EXPIRE_ACCESS_TOKEN )) // 5 min
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", appUser.getAppRoles().stream().map(r -> r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String,String> tokens = new HashMap<>();
                tokens.put("access-token",jwtAccessToken);
                tokens.put("refresh-token",token);

                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(),tokens);

//                StringBuilder sb = new StringBuilder();
//                sb.append("{ ");
//                sb.append("\"error\": \"Unauthorized\" ");
//                sb.append("\"message\": \"Unauthorized\"");
//                sb.append("\"path\": \"")
//                        .append(request.getRequestURL())
//                        .append("\"");
//                sb.append("} ");
//
//                response.setContentType("application/json");
//                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                response.getWriter().write(sb.toString());


            } catch (Exception e) {
                throw e;
            }
        }else {
            log.error("Refresh token Required !!");
            throw new RuntimeException("Refresh token required !!");

        }
    }

}

@Data
class RoleToUserForm {
    private String username;
    private String rolename;
}
