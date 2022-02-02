package com.keyup.auth.config;

import com.keyup.auth.filters.JWTAuthenticationFilter;
import com.keyup.auth.filters.JWTAuthorizationFilter;
import com.keyup.auth.service.JWTService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JWTService jwtService;

    @Value("${app.security.secret-key}")
    private String secretKey;

    @Value("${app.security.time-expiration}")
    private String timeExpiration;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeRequests().antMatchers().permitAll()
                .anyRequest().authenticated().and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtService, secretKey, Long.parseLong(timeExpiration)))
                .addFilter(new JWTAuthorizationFilter(authenticationManager(), jwtService, secretKey))
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Se define la clase que recupera los usuarios y el algoritmo para procesar las passwords
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(bCryptPasswordEncoder());
    }
}


    /*@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()// Función csrf desactivada
                .authorizeRequests()// Limita la solicitud de firma exitosa
                .antMatchers("/decision/**","/govern/**").hasAnyRole("USER","ADMIN")// Se requieren permisos de USUARIO o ADMINISTRADOR para las interfaces bajo decisión y gobierno
                .antMatchers("/admin/login").permitAll()///admin/el inicio de sesión no está limitado
                .antMatchers("/admin/**").hasRole("ADMIN")// Se requiere permiso ADMIN para la interfaz en admin
                .antMatchers("/oauth/**").permitAll()// No intercepte los recursos abiertos de OAuth
                .anyRequest().permitAll()//Otras solicitudes no calificadas, permitir el acceso
                .and().anonymous()//Permitir el acceso anónimo para otras solicitudes sin permisos de configuración
                .and().formLogin()//Utilice la página de inicio de sesión predeterminada de Spring Security
                .and().httpBasic();//Habilitar la autenticación básica http
    }*/

