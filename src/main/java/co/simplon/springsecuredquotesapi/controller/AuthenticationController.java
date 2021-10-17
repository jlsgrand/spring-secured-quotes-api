package co.simplon.springsecuredquotesapi.controller;

import co.simplon.springsecuredquotesapi.controller.dto.AppCredentialsDto;
import co.simplon.springsecuredquotesapi.controller.dto.JWTDto;
import co.simplon.springsecuredquotesapi.model.AppUser;
import co.simplon.springsecuredquotesapi.model.Role;
import co.simplon.springsecuredquotesapi.repository.AppUserRepository;
import co.simplon.springsecuredquotesapi.security.jwt.TokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Optional;

@RestController
@RequestMapping("/authentication")
public class AuthenticationController {

    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    private final PasswordEncoder passwordEncoder;

    private final AppUserRepository appUserRepository;

    public AuthenticationController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder,
                                    AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Point d'entrée API permettant de créer un compte utilisateur standard (pouvant lire les citations)
     *
     * @param newUser l'utilisateur à créer
     * @return l'utilisateur nouvellement créé si le username n'est pas déjà existant
     */
    @PostMapping("/signup")
    public ResponseEntity signUp(@RequestBody AppUser newUser) {
        Optional<AppUser> existingUser = appUserRepository.findByUsernameIgnoreCase(newUser.getUsername());

        // Pour faire simple on renvoie juste un code d'erreur 400, mais il faudrait renvoyer plus d'information pour que l'utilisateur comprenne le pb.
        if (existingUser.isPresent()) {
            return ResponseEntity.badRequest().build();
        } else {
            // On encode le mot de passe pour éviter de l'avoir en clair dans la BDD
            String encryptedPassword = passwordEncoder.encode(newUser.getPassword());
            // On crée un nouvel utilisateur avec le role reader par défaut et le mot de passe hashé
            newUser = new AppUser(newUser.getUsername(), encryptedPassword, Collections.singletonList(Role.ROLE_READER));
            // On sauve l'utilisateur
            appUserRepository.save(newUser);
            return ResponseEntity.ok().build();
        }
    }

    /**
     * Point d'entrée API permettant de récupérer un Token pour avoir accès aux autres méthodes.
     *
     * @param credentials le username et le mot de passe pour être authentifié et recevoir le token
     * @return un JWT si l'authentification se est OK
     */
    @PostMapping("/signin")
    public ResponseEntity<JWTDto> signIn(@RequestBody AppCredentialsDto credentials) {
        // Je tente l'authentification par mot de passe et username
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(credentials.getUsername(), credentials.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Si ça a marché, je peux créer le token à renvoyer au client.
        String jwt = tokenProvider.createToken(authentication);
        return ResponseEntity.ok(new JWTDto(jwt));
    }
}
