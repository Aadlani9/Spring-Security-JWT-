package com.sid.secservic.sec;


import static org.springframework.http.HttpHeaders.AUTHORIZATION;

public class JWTUtil {
    public static final String SECRET = "mySecret1234";
    public static final String AUTH_HEADER = AUTHORIZATION;
    public static final long EXPIRE_ACCESS_TOKEN = 2*60*1000 ;
}
