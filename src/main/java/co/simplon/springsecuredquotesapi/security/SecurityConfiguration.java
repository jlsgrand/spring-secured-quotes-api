package co.simplon.springsecuredquotesapi.security;

import co.simplon.springsecuredquotesapi.model.Role;
import co.simplon.springsecuredquotesapi.security.jwt.JWTConfigurer;
import co.simplon.springsecuredquotesapi.security.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final TokenProvider tokenProvider;

    public SecurityConfiguration(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    /**
     * Je mets à disposition de mon API un objet BCryptPasswordEncoder qui me permettra de hasher les
     * mots de passe.
     *
     * @return l'objet BCryptPasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Permet de définir la hierarchie des rôles.
     * Ici : le rôle ADMIN a au moins les droits du rôle CREATOR qui a au moins les droits du rôle READER
     *
     * @return
     */
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        String hierarchy = "ROLE_ADMIN > ROLE_CREATOR \n ROLE_CREATOR > ROLE_READER";
        roleHierarchy.setHierarchy(hierarchy);
        return roleHierarchy;
    }

    /**
     * Configuration du CROSS ORIGIN pour que le front puisse faire des appels à l'API
     *
     * @return
     */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**").allowedOrigins("https://ecstatic-boyd-4c09dd.netlify.app").allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS");
                registry.addMapping("/admin/**").allowedOrigins("https://ecstatic-boyd-4c09dd.netlify.app").allowedMethods("GET", "OPTIONS");
                registry.addMapping("/authentication/**").allowedOrigins("https://ecstatic-boyd-4c09dd.netlify.app").allowedMethods("POST", "OPTIONS");
            }
        };
    }

    /**
     * Ici, c'est open bar pour les requêttes HTTP avec méthode OPTIONS,
     * et aussi pour accéder à h2-console, et swagger.
     *
     * @param web
     */
    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
                .antMatchers(HttpMethod.OPTIONS, "/**")
                .antMatchers("/*.{js,html}")
                .antMatchers("/h2-console/**")
                .antMatchers("/swagger-ui/index.html");
    }

    /**
     * @param http
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .cors()
                .and()
                .headers()
                .contentSecurityPolicy("default-src 'self'; frame-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:")
                .and()
                .referrerPolicy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                .and()
                .frameOptions()
                .deny()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                // Propre à mon API
                .antMatchers("/authentication").permitAll()
                .antMatchers(HttpMethod.GET, "/api/**").authenticated()
                .antMatchers(HttpMethod.POST, "/api/**").hasAuthority(Role.ROLE_CREATOR.getAuthority())
                .antMatchers(HttpMethod.PUT, "/api/**").hasAuthority(Role.ROLE_CREATOR.getAuthority())
                .antMatchers(HttpMethod.DELETE, "/api/**").hasAuthority(Role.ROLE_CREATOR.getAuthority())
                .antMatchers("/admin/**").hasAuthority(Role.ROLE_ADMIN.getAuthority())
                .and()
                .apply(securityConfigurerAdapter());
    }

    private JWTConfigurer securityConfigurerAdapter() {
        return new JWTConfigurer(tokenProvider);
    }
}
