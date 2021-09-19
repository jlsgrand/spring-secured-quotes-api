package co.simplon.springsecuredquotesapi;

import co.simplon.springsecuredquotesapi.model.AppUser;
import co.simplon.springsecuredquotesapi.model.Quote;
import co.simplon.springsecuredquotesapi.model.Role;
import co.simplon.springsecuredquotesapi.repository.AppUserRepository;
import co.simplon.springsecuredquotesapi.repository.QuoteRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@SpringBootApplication
public class SpringSecuredQuotesApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecuredQuotesApiApplication.class, args);
    }

    @Bean
    public CommandLineRunner loadData(AppUserRepository appUserRepository, PasswordEncoder passwordEncoder, QuoteRepository quoteRepository) {
        return (args) -> {
            AppUser admin = appUserRepository.save(new AppUser("admin", passwordEncoder.encode("admin"), List.of(Role.ROLE_ADMIN)));
            AppUser creator = appUserRepository.save(new AppUser("creator", passwordEncoder.encode("creator"), List.of(Role.ROLE_CREATOR)));
            appUserRepository.save(new AppUser("reader", passwordEncoder.encode("reader"), List.of(Role.ROLE_READER)));

            quoteRepository.save(new Quote("Dikkenek", "Tu sors ou j'te sors mais va falloir prendre une décision maintenant", admin));
            quoteRepository.save(new Quote("Dikkenek", "Il est tout à fait fou c'type là", admin));
            quoteRepository.save(new Quote("La cité de la peur", "Tu fais super bien le chat", creator));
            quoteRepository.save(new Quote("La cité de la peur", "Euh, moi j'avais voté il bluffe pas", creator));
        };
    }
}
